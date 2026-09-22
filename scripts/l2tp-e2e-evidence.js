#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const TARGET = 'test';
const HOST_IDENTITY = 'test.infograd.online';
const EVIDENCE_CONTOUR = Object.freeze({
    preflight: ['preflight'],
    install: ['install'],
    health: ['l2tp_ipsec_established', 'rollback_recovery'],
    traffic: ['tcp', 'udp', 'dns', 'quic', 'direct_ppp_egress_fail_closed'],
});
const EVIDENCE_TYPES = Object.freeze(Object.keys(EVIDENCE_CONTOUR));
const ALLOWED_ARGUMENTS = Object.freeze(new Set([
    'target',
    'host-identity',
    ...EVIDENCE_TYPES.map(type => `${type}-result`),
]));
const REQUIRED_GATES = Object.freeze([
    'l2tp_ipsec_established',
    'tcp',
    'udp',
    'dns',
    'quic',
    'direct_ppp_egress_fail_closed',
    'rollback_recovery',
]);
const ROOT_FIELDS = Object.freeze([
    'schemaVersion',
    'evidenceType',
    'target',
    'hostIdentity',
    'runId',
    'observedAt',
    'results',
]);
const RESULT_FIELDS = Object.freeze([
    'gate',
    'status',
    'exitCode',
    'commandOutputSha256',
]);

function parseArgs(argv) {
    const options = {};
    for (let index = 0; index < argv.length; index += 2) {
        const flag = argv[index];
        const value = argv[index + 1];
        if (!flag?.startsWith('--') || value === undefined) {
            throw new Error('arguments must be provided as --name value pairs');
        }
        const name = flag.slice(2);
        if (!ALLOWED_ARGUMENTS.has(name)) throw new Error(`unsupported argument: --${name}`);
        if (Object.hasOwn(options, name)) throw new Error(`duplicate argument: --${name}`);
        options[name] = value;
    }
    return options;
}

function sha256(content) {
    return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(value, fields) {
    if (!isPlainObject(value)) return false;
    const actual = Object.keys(value).sort();
    const expected = [...fields].sort();
    return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function isCanonicalTimestamp(value) {
    if (typeof value !== 'string') return false;
    const parsed = new Date(value);
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

function validateEvidence(document, expectedType) {
    const errors = [];
    if (!hasExactFields(document, ROOT_FIELDS)) {
        return { errors: [`${expectedType} evidence does not match the strict top-level schema`] };
    }
    if (document.schemaVersion !== 1) errors.push(`${expectedType} schemaVersion must be 1`);
    if (document.evidenceType !== expectedType) errors.push(`${expectedType} evidenceType mismatch`);
    if (document.target !== TARGET) errors.push(`${expectedType} target mismatch`);
    if (document.hostIdentity !== HOST_IDENTITY) errors.push(`${expectedType} host identity mismatch`);
    if (typeof document.runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(document.runId)) {
        errors.push(`${expectedType} runId is invalid`);
    }
    if (!isCanonicalTimestamp(document.observedAt)) errors.push(`${expectedType} observedAt must be a canonical ISO timestamp`);
    if (!Array.isArray(document.results)) {
        errors.push(`${expectedType} results must be an array`);
        return { errors };
    }

    const expectedGates = EVIDENCE_CONTOUR[expectedType];
    const actualGates = [];
    for (const result of document.results) {
        if (!hasExactFields(result, RESULT_FIELDS)) {
            errors.push(`${expectedType} result does not match the strict schema`);
            continue;
        }
        actualGates.push(result.gate);
        if (!expectedGates.includes(result.gate)) errors.push(`${expectedType} contains an unexpected gate`);
        if (!['pass', 'fail', 'unknown'].includes(result.status)) {
            errors.push(`${expectedType} gate status must be pass, fail, or unknown`);
        }
        if (!/^sha256:[a-f0-9]{64}$/.test(result.commandOutputSha256)) {
            errors.push(`${expectedType} gate command output digest is invalid`);
        }
        if (result.status === 'pass' && result.exitCode !== 0) {
            errors.push(`${expectedType} passing gate must have exitCode 0`);
        } else if (result.status === 'fail'
            && (!Number.isInteger(result.exitCode) || result.exitCode < 1 || result.exitCode > 255)) {
            errors.push(`${expectedType} failing gate must have exitCode 1..255`);
        } else if (result.status === 'unknown' && result.exitCode !== null) {
            errors.push(`${expectedType} unknown gate must have a null exitCode`);
        }
    }

    const uniqueActualGates = [...new Set(actualGates)];
    if (uniqueActualGates.length !== actualGates.length) errors.push(`${expectedType} contains duplicate gates`);
    if (expectedGates.some(gate => !uniqueActualGates.includes(gate))) {
        errors.push(`${expectedType} is missing required gates`);
    }
    if (actualGates.length !== expectedGates.length) errors.push(`${expectedType} gate count mismatch`);

    return { errors };
}

function failedReport(target, hostIdentity, errors, extra = {}) {
    return {
        schemaVersion: 1,
        target: target ?? null,
        hostIdentity: hostIdentity ?? null,
        passed: false,
        errors,
        ...extra,
    };
}

function emptySummary(evidenceType) {
    return {
        status: 'unknown',
        exitCode: null,
        commandOutputSha256: null,
        evidenceType,
        evidencePresent: false,
    };
}

function createReport() {
    const gates = {};
    for (const gate of REQUIRED_GATES) {
        const evidenceType = EVIDENCE_CONTOUR.health.includes(gate) ? 'health' : 'traffic';
        gates[gate] = emptySummary(evidenceType);
    }
    return {
        schemaVersion: 1,
        target: TARGET,
        hostIdentity: HOST_IDENTITY,
        runId: null,
        passed: false,
        evidence: {},
        checks: {
            preflight: emptySummary('preflight'),
            install: emptySummary('install'),
        },
        gates,
        missingEvidence: [],
        failedChecks: [],
        failedGates: [],
        unknownGates: [],
        errors: [],
    };
}

function finalizeReport(report) {
    report.failedChecks = ['preflight', 'install']
        .filter(check => report.checks[check].status !== 'pass');
    report.failedGates = REQUIRED_GATES
        .filter(gate => report.gates[gate].status === 'fail');
    report.unknownGates = REQUIRED_GATES
        .filter(gate => report.gates[gate].status === 'unknown');
    report.passed = report.errors.length === 0
        && report.missingEvidence.length === 0
        && report.failedChecks.length === 0
        && report.failedGates.length === 0
        && report.unknownGates.length === 0;
    return report;
}

function run(argv) {
    let options;
    try {
        options = parseArgs(argv);
    } catch (error) {
        return failedReport(null, null, [error.message]);
    }

    if (options.target !== TARGET) {
        return failedReport(options.target, options['host-identity'], ['--target must be exactly test']);
    }
    if (options['host-identity'] !== HOST_IDENTITY) {
        return failedReport(options.target, options['host-identity'], [
            '--host-identity must be exactly test.infograd.online',
        ]);
    }

    const missingEvidence = EVIDENCE_TYPES.filter(type => !options[`${type}-result`]);
    if (missingEvidence.length > 0) {
        const report = createReport();
        report.missingEvidence.push(...missingEvidence);
        report.errors.push(`missing required evidence: ${missingEvidence.join(', ')}`);
        return finalizeReport(report);
    }

    const report = createReport();

    for (const evidenceType of EVIDENCE_TYPES) {
        let content;
        try {
            content = fs.readFileSync(options[`${evidenceType}-result`]);
        } catch {
            report.missingEvidence.push(evidenceType);
            report.errors.push(`unable to read ${evidenceType} evidence file`);
            continue;
        }

        report.evidence[evidenceType] = { sourceFileSha256: sha256(content) };
        let document;
        try {
            document = JSON.parse(content.toString('utf8'));
        } catch {
            report.errors.push(`${evidenceType} evidence is not valid JSON`);
            continue;
        }

        const validation = validateEvidence(document, evidenceType);
        if (validation.errors.length > 0) {
            report.errors.push(...validation.errors);
            continue;
        }
        report.evidence[evidenceType].observedAt = document.observedAt;
        if (report.runId === null) report.runId = document.runId;
        if (report.runId !== document.runId) {
            report.errors.push(`${evidenceType} runId does not match the evidence set`);
            continue;
        }

        for (const result of document.results) {
            const summary = {
                status: result.status,
                exitCode: result.exitCode,
                commandOutputSha256: result.commandOutputSha256,
                evidenceType,
                evidencePresent: true,
            };
            if (evidenceType === 'preflight' || evidenceType === 'install') {
                report.checks[result.gate] = summary;
            } else {
                report.gates[result.gate] = summary;
            }
        }
    }

    return finalizeReport(report);
}

if (require.main === module) {
    const report = run(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = report.passed ? 0 : 1;
}

module.exports = {
    EVIDENCE_CONTOUR,
    REQUIRED_GATES,
    parseArgs,
    run,
    sha256,
    validateEvidence,
};
