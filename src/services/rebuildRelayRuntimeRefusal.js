'use strict';

const runtimeForeignChange = 'REBUILD_L2TP_RUNTIME_FOREIGN_CHANGE';
const networkObservationRequired = 'NETWORK_OBSERVATION_REQUIRED';
const hostNotReady = 'REBUILD_L2TP_HOST_NOT_READY';
const networkNotReadyDetails = Object.freeze({ code: hostNotReady, check: networkObservationRequired, retryAllowed: false });
const isNetworkObservationRequired = error => error?.code === `REBUILD_L2TP_DIRECT_${networkObservationRequired}`
    && error.outcome === undefined && error.remoteOutcomeUncertain !== true;
const isNetworkNotReady = error => error?.code === hostNotReady && error.check === networkObservationRequired
    && error.retryAllowed === false && error.outcome === undefined && error.remoteOutcomeUncertain !== true;
const isRuntimeForeignChange = error => error?.code === 'REBUILD_L2TP_DIRECT_RUNTIME_FOREIGN_CHANGE'
    && error.outcome === undefined && error.remoteOutcomeUncertain !== true;
const isUnconfirmedRuntimeWrite = error => error?.code === 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN'
    && error.remoteOutcomeUncertain === true;

module.exports = { runtimeForeignChange, isRuntimeForeignChange, isUnconfirmedRuntimeWrite,
    networkObservationRequired, networkNotReadyDetails, isNetworkObservationRequired, isNetworkNotReady };