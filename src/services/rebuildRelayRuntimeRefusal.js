'use strict';

const runtimeForeignChange = 'REBUILD_L2TP_RUNTIME_FOREIGN_CHANGE';
const isRuntimeForeignChange = error => error?.code === 'REBUILD_L2TP_DIRECT_RUNTIME_FOREIGN_CHANGE'
    && error.outcome === undefined && error.remoteOutcomeUncertain !== true;
const isUnconfirmedRuntimeWrite = error => error?.code === 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN'
    && error.remoteOutcomeUncertain === true;

module.exports = { runtimeForeignChange, isRuntimeForeignChange, isUnconfirmedRuntimeWrite };