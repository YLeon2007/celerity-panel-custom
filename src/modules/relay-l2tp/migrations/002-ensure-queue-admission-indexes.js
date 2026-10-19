'use strict';

const QUEUE_ADMISSION_MODEL_NAMES = Object.freeze([
    'TopologyCreateIntent',
    'TopologyIntentQueueState',
    'RemoteAdmission',
]);

// Additive: never edit/replay 001, and never infer legacy admission counters.
const ensureQueueAdmissionIndexes = Object.freeze({
    id: '002-ensure-queue-admission-indexes',
    version: 2,
    steps: Object.freeze(QUEUE_ADMISSION_MODEL_NAMES.map(modelName => Object.freeze({
        action: 'createIndexes', modelName,
    }))),
});

module.exports = { ensureQueueAdmissionIndexes, QUEUE_ADMISSION_MODEL_NAMES };
