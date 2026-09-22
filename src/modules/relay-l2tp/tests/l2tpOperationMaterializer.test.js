'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    materializeInstallOperation,
} = require('../services/l2tpOperationMaterializer');
const {
    buildInstallPlan,
} = require('../services/l2tpProvisionPlanService');

const SECRET_PSK = 'psk-do-not-persist-7a69';
const SECRET_PASSWORD = 'password-do-not-persist-4c21';

function desired(overrides = {}) {
    return {
        desiredState: 'installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        secretRevision: 9,
        psk: SECRET_PSK,
        users: [{
            login: 'alice',
            password: SECRET_PASSWORD,
            ipAddress: '10.77.0.10',
            enabled: true,
        }],
        ...overrides,
    };
}

function planFor(candidateDesired = desired()) {
    return buildInstallPlan({
        operationId: 'operation-17',
        topologyRevision: 17,
        relay: { id: 'relay-1', role: 'relay' },
        routeGroup: { id: 'group-a' },
        relayGroupPlan: {
            groupId: 'group-a',
            candidates: [{
                pathKey: 'primary',
                healthy: true,
                nextHopNodeId: 'bridge-1',
            }],
            decision: {
                decision: 'select',
                groupId: 'group-a',
                pathKey: 'primary',
                nextHopNodeId: 'bridge-1',
            },
        },
        desired: candidateDesired,
    });
}

test('prepares a durable install plan with typed artifact references and no secret values', () => {
    const candidateDesired = desired();

    const result = materializeInstallOperation({
        plan: planFor(candidateDesired),
        desired: candidateDesired,
    });

    assert.deepEqual(result.persistedPlan.desired, {
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        credentialRevision: 9,
    });
    assert.deepEqual(
        result.persistedPlan.steps.find(step => step.type === 'preflight'),
        {
            type: 'preflight',
            artifacts: [{ type: 'desired', path: 'desired.json' }],
        },
    );
    assert.deepEqual(
        result.persistedPlan.steps.find(step => step.type === 'stage_managed_files'),
        {
            type: 'stage_managed_files',
            artifacts: [{ type: 'artifact', path: 'artifacts.json' }],
        },
    );
    assert.deepEqual(result.remoteArtifacts, []);

    const serializedPlan = JSON.stringify(result.persistedPlan);
    assert.doesNotMatch(serializedPlan, new RegExp(SECRET_PSK));
    assert.doesNotMatch(serializedPlan, new RegExp(SECRET_PASSWORD));
    assert.doesNotMatch(serializedPlan, /"(?:psk|password|content)"\s*:/i);
});

test('materializes fixed preflight JSON and generated artifacts only after secrets resolve', () => {
    const candidateDesired = desired();
    const prepared = materializeInstallOperation({
        plan: planFor(candidateDesired),
        desired: candidateDesired,
    });
    const buildCalls = [];
    const generatedArtifacts = {
        files: [{
            path: 'etc/ipsec.secrets',
            mode: 0o600,
            content: `%any %any : PSK "${SECRET_PSK}"\n`,
        }],
        metadata: { namespace: 'celerity_l2tp' },
    };

    const result = materializeInstallOperation({
        plan: prepared.persistedPlan,
        secrets: {
            psk: SECRET_PSK,
            users: [{ login: 'alice', password: SECRET_PASSWORD }],
        },
    }, {
        buildArtifacts(resolvedDesired) {
            buildCalls.push(resolvedDesired);
            return generatedArtifacts;
        },
    });

    assert.deepEqual(buildCalls, [{
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        psk: SECRET_PSK,
    }]);
    assert.deepEqual(result.persistedPlan, prepared.persistedPlan);
    assert.deepEqual(result.remoteArtifacts, [
        {
            stepType: 'preflight',
            type: 'desired',
            path: 'desired.json',
            content: '{"clientCidr":"10.77.0.0/24"}\n',
        },
        {
            stepType: 'stage_managed_files',
            type: 'artifact',
            path: 'artifacts.json',
            content: `${JSON.stringify(generatedArtifacts)}\n`,
        },
    ]);
    assert.doesNotMatch(result.remoteArtifacts[0].content, /psk|password|secret/i);
    assert.match(result.remoteArtifacts[1].content, new RegExp(SECRET_PSK));
    assert.doesNotMatch(JSON.stringify(result.persistedPlan), new RegExp(SECRET_PSK));
    assert.doesNotMatch(JSON.stringify(result.persistedPlan), new RegExp(SECRET_PASSWORD));
});
