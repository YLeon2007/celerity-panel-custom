'use strict';

const MAX_PREFLIGHT_OUTPUT_BYTES = 16 * 1024;
const SUCCESS_SEQUENCE = Object.freeze([
    'os',
    'client_cidr',
    'xray',
    'xray_config',
    'xray_unit',
]);
const ERROR_CODES_BY_CHECK = Object.freeze({
    input: new Set(['INVALID_ARGUMENTS']),
    desired_state: new Set([
        'INVALID_DESIRED_STATE_FILE',
        'DESIRED_STATE_NOT_ROOT_OWNED',
        'INVALID_CLIENT_CIDR',
    ]),
    os: new Set(['UNSUPPORTED_OS']),
    xray: new Set(['XRAY_BINARY_MISSING', 'XRAY_VERSION_UNAVAILABLE']),
    xray_config: new Set(['XRAY_CONFIG_MISSING', 'XRAY_CONFIG_INVALID']),
    xray_unit: new Set(['XRAY_UNIT_MISSING']),
});
const ERROR_PREFIX_BY_CHECK = Object.freeze({
    input: [],
    desired_state: ['os'],
    os: [],
    xray: ['os', 'client_cidr'],
    xray_config: ['os', 'client_cidr', 'xray'],
    xray_unit: ['os', 'client_cidr', 'xray', 'xray_config'],
});

function isNonArrayObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSafeText(value, maxLength) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= maxLength
        && !/[\u0000-\u001f\u007f]/.test(value);
}

function parseIpv4(value) {
    if (typeof value !== 'string') return null;
    const octets = value.split('.');
    if (octets.length !== 4 || octets.some(octet => !/^(0|[1-9]\d{0,2})$/.test(octet))) {
        return null;
    }
    const numbers = octets.map(Number);
    if (numbers.some(octet => octet > 255)) return null;
    return numbers.reduce((address, octet) => (address * 256) + octet, 0);
}

function isCanonicalIpv4Cidr(value) {
    if (typeof value !== 'string') return false;
    const match = value.match(/^([^/]+)\/(\d|[12]\d|3[0-2])$/);
    if (!match) return false;
    const address = parseIpv4(match[1]);
    if (address === null) return false;
    const blockSize = 2 ** (32 - Number(match[2]));
    return address === Math.floor(address / blockSize) * blockSize;
}

function sanitizeOkCheck(check) {
    switch (check.check) {
    case 'os':
        if (
            !isSafeText(check.id, 64)
            || !/^[a-z0-9][a-z0-9._-]*$/.test(check.id)
            || !isSafeText(check.version, 128)
        ) return null;
        return {
            check: 'os',
            status: 'ok',
            id: check.id,
            version: check.version,
        };
    case 'client_cidr':
        if (!isCanonicalIpv4Cidr(check.cidr)) return null;
        return { check: 'client_cidr', status: 'ok', cidr: check.cidr };
    case 'xray':
        if (!isSafeText(check.version, 256)) return null;
        return { check: 'xray', status: 'ok', version: check.version };
    case 'xray_config':
        if (check.path !== '/usr/local/etc/xray/config.json') return null;
        return {
            check: 'xray_config',
            status: 'ok',
            path: '/usr/local/etc/xray/config.json',
        };
    case 'xray_unit':
        if (check.unit !== 'xray.service') return null;
        return { check: 'xray_unit', status: 'ok', unit: 'xray.service' };
    default:
        return null;
    }
}

function sanitizeErrorCheck(check) {
    if (!ERROR_CODES_BY_CHECK[check.check]?.has(check.code)) return null;
    const sanitized = {
        check: check.check,
        status: 'error',
        code: check.code,
    };
    if (check.check === 'os') {
        if (
            !isSafeText(check.id, 64)
            || !/^[a-z0-9][a-z0-9._-]*$/.test(check.id)
            || !isSafeText(check.version, 128)
        ) return null;
        sanitized.id = check.id;
        sanitized.version = check.version;
    }
    return sanitized;
}

function sanitizePreflightCheck(check) {
    if (!isNonArrayObject(check)) return null;
    if (check.status === 'ok') return sanitizeOkCheck(check);
    if (check.status === 'error') return sanitizeErrorCheck(check);
    return null;
}

function isSuccessSequence(checks) {
    return checks.length === SUCCESS_SEQUENCE.length
        && checks.every((check, index) => (
            check.status === 'ok' && check.check === SUCCESS_SEQUENCE[index]
        ));
}

function isFailureSequence(checks) {
    if (checks.length === 0) return false;
    const failed = checks[checks.length - 1];
    if (failed.status !== 'error') return false;
    const prefix = ERROR_PREFIX_BY_CHECK[failed.check];
    return prefix !== undefined
        && checks.length === prefix.length + 1
        && checks.slice(0, -1).every((check, index) => (
            check.status === 'ok' && check.check === prefix[index]
        ));
}

function invalidPreflightResponse() {
    return {
        ok: false,
        checks: [],
        error: { code: 'PREFLIGHT_RESPONSE_INVALID' },
    };
}

function sanitizePreflightResult(result) {
    if (!isNonArrayObject(result) || !Array.isArray(result.checks)) return null;
    const checks = result.checks.map(sanitizePreflightCheck);
    if (checks.some(check => check === null)) return null;

    if (result.ok === true) {
        return isSuccessSequence(checks) ? { ok: true, checks } : null;
    }
    if (result.ok !== false || !isNonArrayObject(result.error)) return null;

    if (result.error.code === 'PREFLIGHT_RESPONSE_INVALID' && checks.length === 0) {
        return invalidPreflightResponse();
    }
    if (!isFailureSequence(checks)) return null;
    const failed = checks[checks.length - 1];
    if (result.error.code !== failed.code) return null;
    return {
        ok: false,
        checks,
        error: { code: failed.code },
    };
}

function parsePreflightExecResult(result) {
    if (
        !isNonArrayObject(result)
        || !Number.isSafeInteger(result.code)
        || typeof result.stdout !== 'string'
        || Buffer.byteLength(result.stdout, 'utf8') > MAX_PREFLIGHT_OUTPUT_BYTES
    ) {
        return invalidPreflightResponse();
    }

    const lines = result.stdout.trimEnd().split('\n');
    if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {
        return invalidPreflightResponse();
    }

    let checks;
    try {
        checks = lines.map(line => JSON.parse(line));
    } catch {
        return invalidPreflightResponse();
    }

    const candidate = result.code === 0
        ? { ok: true, checks }
        : {
            ok: false,
            checks,
            error: { code: checks[checks.length - 1]?.code },
        };
    return sanitizePreflightResult(candidate) ?? invalidPreflightResponse();
}

module.exports = {
    MAX_PREFLIGHT_OUTPUT_BYTES,
    invalidPreflightResponse,
    parsePreflightExecResult,
    sanitizePreflightResult,
};
