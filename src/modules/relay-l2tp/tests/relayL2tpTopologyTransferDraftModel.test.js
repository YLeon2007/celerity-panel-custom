'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const TopologyTransferDraft = require('../models/relayL2tpTopologyTransferDraftModel');

function validDocument(kind = 'relay-l2tp-topology-import-draft') {
    return {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind,
        topology: { nodes: [], links: [], routeGroups: [], relayStates: [] },
    };
}

function validDraft(overrides = {}) {
    return {
        draftId: '4ac7d68f-5c40-47e7-a329-6daf108b09dd',
        status: 'DRAFT',
        source: 'import',
        name: 'Imported topology',
        document: validDocument(),
        counts: { nodes: 0, links: 0, routeGroups: 0, relayStates: 0 },
        ...overrides,
    };
}

test('registers the collision-free transfer draft model and collection', () => {
    assert.equal(TopologyTransferDraft.modelName, 'RelayL2tpTopologyTransferDraft');
    assert.equal(
        TopologyTransferDraft.collection.collectionName,
        'relayL2tpTopologyTransferDrafts',
    );
    assert.equal(new TopologyTransferDraft(validDraft()).validateSync(), undefined);

    const publicIdIndex = TopologyTransferDraft.schema.indexes()
        .find(([fields]) => fields.draftId === 1);
    assert.ok(publicIdIndex);
    assert.equal(publicIdIndex[1].unique, true);
});

test('permits only immutable canonical DRAFT records', () => {
    const schema = TopologyTransferDraft.schema;
    for (const field of ['draftId', 'status', 'source', 'name', 'document', 'counts']) {
        assert.equal(schema.path(field).options.immutable, true, field);
    }

    for (const fields of [
        { status: 'APPLIED' },
        { draftId: '64a1b2c3d4e5f6a7b8c9d001' },
        { source: 'deploy' },
        {
            document: {
                ...validDocument(),
                credentials: { token: 'must-not-be-stored' },
            },
        },
        {
            counts: { nodes: 1, links: 0, routeGroups: 0, relayStates: 0 },
        },
    ]) {
        const error = new TopologyTransferDraft(validDraft(fields)).validateSync();
        assert.ok(error, JSON.stringify(fields));
    }
});

test('accepts canonical export drafts only when source and document kind agree', () => {
    const exported = new TopologyTransferDraft(validDraft({
        source: 'export',
        document: validDocument('relay-l2tp-topology-transfer'),
    }));
    assert.equal(exported.validateSync(), undefined);

    const mismatch = new TopologyTransferDraft(validDraft({
        source: 'export',
        document: validDocument('relay-l2tp-topology-import-draft'),
    }));
    assert.ok(mismatch.validateSync());
});
