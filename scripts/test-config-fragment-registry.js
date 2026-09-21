'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createConfigFragmentRegistry } = require('../src/services/configFragmentRegistry');

test('registers a known named provider exactly once', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);

    registry.register('relay-l2tp', () => ({ id: 'relay-l2tp', inbounds: [] }));

    assert.deepEqual(registry.compose({ revision: 1 }), [
        { id: 'relay-l2tp', inbounds: [] },
    ]);
});

test('rejects an unknown provider with a structured error', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);

    assert.throws(
        () => registry.register('unknown', () => ({ id: 'unknown' })),
        {
            name: 'ConfigFragmentRegistryError',
            code: 'UNKNOWN_CONFIG_FRAGMENT_PROVIDER',
            providerId: 'unknown',
        },
    );
});

test('rejects duplicate provider registration with a structured error', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);
    const provider = () => ({ id: 'relay-l2tp' });
    registry.register('relay-l2tp', provider);

    assert.throws(
        () => registry.register('relay-l2tp', provider),
        {
            name: 'ConfigFragmentRegistryError',
            code: 'DUPLICATE_CONFIG_FRAGMENT_PROVIDER',
            providerId: 'relay-l2tp',
        },
    );
});

test('passes a deeply frozen snapshot to providers', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);
    let receivedSnapshot;
    registry.register('relay-l2tp', snapshot => {
        receivedSnapshot = snapshot;
        return { id: 'relay-l2tp' };
    });

    registry.compose({
        revision: 7,
        topology: { links: [{ id: 'link-1' }] },
    });

    assert.equal(Object.isFrozen(receivedSnapshot), true);
    assert.equal(Object.isFrozen(receivedSnapshot.topology), true);
    assert.equal(Object.isFrozen(receivedSnapshot.topology.links), true);
    assert.equal(Object.isFrozen(receivedSnapshot.topology.links[0]), true);
    assert.throws(() => {
        receivedSnapshot.topology.links[0].id = 'mutated';
    }, TypeError);
});

test('composes fragments deterministically in provider id order', () => {
    const registry = createConfigFragmentRegistry(['zeta', 'alpha']);
    registry.register('zeta', () => ({ id: 'zeta', rules: ['z'] }));
    registry.register('alpha', () => ({ id: 'alpha', rules: ['a'] }));

    assert.deepEqual(registry.compose({}), [
        { id: 'alpha', rules: ['a'] },
        { id: 'zeta', rules: ['z'] },
    ]);
});

test('rejects a fragment whose id does not match its registered provider', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);
    registry.register('relay-l2tp', () => ({ id: 'another-provider' }));

    assert.throws(
        () => registry.compose({}),
        {
            name: 'ConfigFragmentRegistryError',
            code: 'CONFIG_FRAGMENT_PROVIDER_ID_MISMATCH',
            providerId: 'relay-l2tp',
            fragmentId: 'another-provider',
        },
    );
});

test('rejects a fragment without provider ownership id', () => {
    const registry = createConfigFragmentRegistry(['relay-l2tp']);
    registry.register('relay-l2tp', () => ({ inbounds: [] }));

    assert.throws(
        () => registry.compose({}),
        error => (
            error.name === 'ConfigFragmentRegistryError'
            && error.code === 'CONFIG_FRAGMENT_PROVIDER_ID_MISMATCH'
            && error.providerId === 'relay-l2tp'
            && error.fragmentId === undefined
        ),
    );
});
