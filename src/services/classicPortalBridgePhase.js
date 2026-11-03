'use strict';

// Process-local provenance, NOT an error.code/property supplied by a transport
// or public request. Only a caller supplying the separate trusted callback may
// use this proof; legacy callers conservatively retain unknown completion.
const noRemoteMutation = new WeakSet();
function createClassicPortalBridgePhase(context) {
    const before = context?.beforeRemoteMutation;
    let dispatched = false;
    return Object.freeze({
        async beforeDispatch(nodeId, phase) {
            if (typeof before === 'function') await before(Object.freeze({ nodeId, phase }));
            // Sticky across nodes and all later failures, including same-node
            // staging failures. A thrown callback never authorizes this dispatch.
            dispatched = true;
        },
        failure(error) {
            if (typeof before === 'function' && !dispatched && error && (typeof error === 'object' || typeof error === 'function')) {
                noRemoteMutation.add(error);
            } else {
                // An adapter may reuse an Error from a prior no-write attempt.
                // It must not carry that provenance into a mutating invocation.
                noRemoteMutation.delete(error);
            }
            return error;
        },
    });
}
function isClassicPortalBridgePreflightError(error) {
    return !!error && noRemoteMutation.has(error);
}
module.exports = { createClassicPortalBridgePhase, isClassicPortalBridgePreflightError };
