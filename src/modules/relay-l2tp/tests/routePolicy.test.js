'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { selectActivePath } = require('../domain/routePolicy');

function path(key, priority, overrides = {}) {
    return {
        key,
        priority,
        enabled: true,
        complete: true,
        ...overrides,
    };
}

test('selects only the healthy enabled complete path with the lowest numeric priority', () => {
    const paths = [
        path('disabled', 1, { enabled: false }),
        path('incomplete', 2, { complete: false }),
        path('unhealthy', 3),
        path('non-numeric', '4'),
        path('secondary', 20),
        path('primary', 10),
    ];
    const healthByPathKey = {
        disabled: true,
        incomplete: true,
        unhealthy: false,
        'non-numeric': true,
        secondary: true,
        primary: true,
    };

    assert.deepEqual(selectActivePath(paths, healthByPathKey), {
        decision: 'select',
        pathKey: 'primary',
    });
});

test('selection is independent of input ordering', () => {
    const paths = [
        path('tertiary', 30),
        path('primary', 10),
        path('secondary', 20),
    ];
    const healthByPathKey = {
        primary: true,
        secondary: true,
        tertiary: true,
    };

    assert.deepEqual(
        selectActivePath(paths, healthByPathKey),
        selectActivePath([...paths].reverse(), healthByPathKey),
    );
    assert.deepEqual(selectActivePath(paths, healthByPathKey), {
        decision: 'select',
        pathKey: 'primary',
    });
});

test('blocks fail-closed when no path is eligible', () => {
    assert.deepEqual(
        selectActivePath(
            [path('disabled', 1, { enabled: false }), path('unhealthy', 2)],
            { disabled: true, unhealthy: false },
        ),
        {
            decision: 'block',
            error: { code: 'NO_HEALTHY_PATH' },
        },
    );
});

test('blocks with a deterministic structured error for equal eligible priorities', () => {
    const paths = [
        path('path-b', 10),
        path('path-a', 10),
        path('path-c', 20),
    ];
    const healthByPathKey = {
        'path-a': true,
        'path-b': true,
        'path-c': true,
    };

    assert.deepEqual(selectActivePath(paths, healthByPathKey), {
        decision: 'block',
        error: {
            code: 'DUPLICATE_PRIORITY',
            priority: 10,
            pathKeys: ['path-a', 'path-b'],
        },
    });
});
