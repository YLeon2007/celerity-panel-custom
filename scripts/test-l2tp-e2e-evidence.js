'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const harnessScript = path.join(repoRoot, 'scripts', 'l2tp-e2e-evidence.js');
const schemaPath = path.join(repoRoot, 'scripts', 'l2tp-e2e', 'evidence.schema.json');

function runHarness(args) {
    return spawnSync(process.execPath, [harnessScript, ...args], {
        cwd: repoRoot,
        encoding: 'utf8',
    });
}

function parseReport(result) {
    assert.ok(result.stdout, result.stderr);
    return JSON.parse(result.stdout);
}

function digest(content) {
    return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function createEvidenceFixture(overrides = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'celerity-l2tp-e2e-evidence-'));
    const runId = 'e2e-20260922T120000Z';
    const definitions = {
        preflight: ['preflight'],
        install: ['install'],
        health: ['l2tp_ipsec_established', 'rollback_recovery'],
        traffic: ['tcp', 'udp', 'dns', 'quic', 'direct_ppp_egress_fail_closed'],
    };
    const files = {};
    const documents = {};

    for (const [evidenceType, gates] of Object.entries(definitions)) {
        const document = {
            schemaVersion: 1,
            evidenceType,
            target: 'test',
            hostIdentity: 'test.infograd.online',
            runId,
            observedAt: '2026-09-22T09:00:00.000Z',
            results: gates.map((gate, index) => ({
                gate,
                status: 'pass',
                exitCode: 0,
                commandOutputSha256: `sha256:${String(index + 1).repeat(64).slice(0, 64)}`,
            })),
        };
        if (overrides[evidenceType]) overrides[evidenceType](document);
        const filePath = path.join(root, `${evidenceType}.json`);
        fs.writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`);
        files[evidenceType] = filePath;
        documents[evidenceType] = document;
    }

    return {
        root,
        files,
        documents,
        args: [
            '--target', 'test',
            '--host-identity', 'test.infograd.online',
            '--preflight-result', files.preflight,
            '--install-result', files.install,
            '--health-result', files.health,
            '--traffic-result', files.traffic,
        ],
        cleanup() {
            fs.rmSync(root, { recursive: true, force: true });
        },
    };
}

test('published evidence schema is strict and pins test identity, statuses, and digest shape', () => {
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.target.const, 'test');
    assert.equal(schema.properties.hostIdentity.const, 'test.infograd.online');
    assert.deepEqual(schema.properties.evidenceType.enum, ['preflight', 'install', 'health', 'traffic']);
    assert.equal(schema.$defs.result.additionalProperties, false);
    assert.deepEqual(schema.$defs.result.properties.status.enum, ['pass', 'fail', 'unknown']);
    assert.equal(schema.$defs.result.properties.commandOutputSha256.pattern, '^sha256:[a-f0-9]{64}$');
    assert.equal(schema.allOf.length, 4);
    const contour = Object.fromEntries(schema.allOf.map(rule => {
        const evidenceType = rule.if.properties.evidenceType.const;
        const gateSchema = rule.then.properties.results.items.properties.gate;
        return [evidenceType, gateSchema.enum ?? [gateSchema.const]];
    }));
    assert.deepEqual(contour, {
        preflight: ['preflight'],
        install: ['install'],
        health: ['l2tp_ipsec_established', 'rollback_recovery'],
        traffic: ['tcp', 'udp', 'dns', 'quic', 'direct_ppp_egress_fail_closed'],
    });
});

test('guard refuses any target other than test before reading evidence', () => {
    const result = runHarness([
        '--target', 'production',
        '--host-identity', 'test.infograd.online',
        '--preflight-result', '/does/not/exist/preflight.json',
    ]);

    assert.notEqual(result.status, 0);
    const report = parseReport(result);
    assert.equal(report.passed, false);
    assert.match(report.errors.join('\n'), /--target must be exactly test/);
    assert.doesNotMatch(report.errors.join('\n'), /ENOENT|not found/i);
});

test('guard refuses any identity other than test.infograd.online before reading evidence', () => {
    const result = runHarness([
        '--target', 'test',
        '--host-identity', 'panel.infograd.online',
        '--preflight-result', '/does/not/exist/preflight.json',
    ]);

    assert.notEqual(result.status, 0);
    const report = parseReport(result);
    assert.equal(report.passed, false);
    assert.match(report.errors.join('\n'), /--host-identity must be exactly test\.infograd\.online/);
    assert.doesNotMatch(report.errors.join('\n'), /ENOENT|not found/i);
});

test('guard refuses unsupported options instead of growing an execution surface', () => {
    const result = runHarness([
        '--target', 'test',
        '--host-identity', 'test.infograd.online',
        '--execute-probes', 'true',
    ]);

    assert.notEqual(result.status, 0);
    const report = parseReport(result);
    assert.equal(report.passed, false);
    assert.match(report.errors.join('\n'), /unsupported argument: --execute-probes/);
    assert.equal(report.evidence, undefined);
});

test('missing required evidence arguments produce a failed report naming every missing source', () => {
    const result = runHarness([
        '--target', 'test',
        '--host-identity', 'test.infograd.online',
    ]);

    assert.notEqual(result.status, 0);
    const report = parseReport(result);
    assert.equal(report.passed, false);
    assert.deepEqual(report.missingEvidence, ['preflight', 'install', 'health', 'traffic']);
    assert.match(report.errors.join('\n'), /missing required evidence/);
    assert.deepEqual(Object.keys(report.gates).sort(), [
        'direct_ppp_egress_fail_closed',
        'dns',
        'l2tp_ipsec_established',
        'quic',
        'rollback_recovery',
        'tcp',
        'udp',
    ]);
    for (const gate of Object.values(report.gates)) {
        assert.equal(gate.status, 'unknown');
        assert.equal(gate.commandOutputSha256, null);
        assert.equal(gate.evidencePresent, false);
    }
});

test('complete schema-valid evidence reports every required gate and stays failed on unknown', () => {
    const fixture = createEvidenceFixture({
        traffic(document) {
            const quic = document.results.find(result => result.gate === 'quic');
            quic.status = 'unknown';
            quic.exitCode = null;
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.deepEqual(report.missingEvidence, []);
        assert.deepEqual(Object.keys(report.gates).sort(), [
            'direct_ppp_egress_fail_closed',
            'dns',
            'l2tp_ipsec_established',
            'quic',
            'rollback_recovery',
            'tcp',
            'udp',
        ]);
        assert.equal(report.gates.quic.status, 'unknown');
        assert.match(report.gates.quic.commandOutputSha256, /^sha256:[a-f0-9]{64}$/);
        assert.deepEqual(report.unknownGates, ['quic']);
        assert.equal(
            report.evidence.preflight.sourceFileSha256,
            digest(fs.readFileSync(fixture.files.preflight)),
        );
        assert.equal(JSON.stringify(report).includes('raw output'), false);
    } finally {
        fixture.cleanup();
    }
});

test('strict schema rejects raw command output without echoing secret material', () => {
    const secret = 'credential-that-must-not-appear';
    const fixture = createEvidenceFixture({
        health(document) {
            document.results[0].rawOutput = secret;
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const serialized = JSON.stringify(parseReport(result));
        assert.match(serialized, /strict schema/);
        assert.equal(serialized.includes(secret), false);
    } finally {
        fixture.cleanup();
    }
});

test('malformed command output digests fail validation', () => {
    const fixture = createEvidenceFixture({
        traffic(document) {
            document.results[0].commandOutputSha256 = 'sha256:not-a-digest';
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.match(report.errors.join('\n'), /command output digest is invalid/);
    } finally {
        fixture.cleanup();
    }
});

test('missing required gates fail closed instead of being inferred', () => {
    const fixture = createEvidenceFixture({
        traffic(document) {
            document.results = document.results.filter(result => result.gate !== 'udp');
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.match(report.errors.join('\n'), /missing required gates/);
        assert.ok(report.unknownGates.includes('udp'));
    } finally {
        fixture.cleanup();
    }
});

test('gate status and command exit code must agree', () => {
    const fixture = createEvidenceFixture({
        install(document) {
            document.results[0].exitCode = 9;
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.match(report.errors.join('\n'), /passing gate must have exitCode 0/);
    } finally {
        fixture.cleanup();
    }
});

test('unreadable result files are classified as missing evidence without leaking paths', () => {
    const fixture = createEvidenceFixture();
    try {
        const args = [...fixture.args];
        args[args.indexOf('--install-result') + 1] = '/private/credentials/install.json';
        const result = runHarness(args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.deepEqual(report.missingEvidence, ['install']);
        assert.match(report.errors.join('\n'), /unable to read install evidence file/);
        assert.doesNotMatch(JSON.stringify(report), /private|credentials|ENOENT/);
    } finally {
        fixture.cleanup();
    }
});

test('evidence files from different runs cannot be combined', () => {
    const fixture = createEvidenceFixture({
        install(document) {
            document.runId = 'e2e-another-run';
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.match(report.errors.join('\n'), /runId does not match the evidence set/);
    } finally {
        fixture.cleanup();
    }
});

test('an explicit failed gate remains failed and makes the aggregate report fail', () => {
    const fixture = createEvidenceFixture({
        traffic(document) {
            const tcp = document.results.find(result => result.gate === 'tcp');
            tcp.status = 'fail';
            tcp.exitCode = 7;
        },
    });
    try {
        const result = runHarness(fixture.args);

        assert.notEqual(result.status, 0);
        const report = parseReport(result);
        assert.equal(report.passed, false);
        assert.equal(report.gates.tcp.status, 'fail');
        assert.deepEqual(report.failedGates, ['tcp']);
    } finally {
        fixture.cleanup();
    }
});
