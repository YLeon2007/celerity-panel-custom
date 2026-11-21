'use strict';

// These exact frames apply only to read-only inspect-chap. Neither arbitrary
// stderr nor the reason itself can authorize a write or settle a pending intent.
const frames = new Map([
    ['DIRECT_CHAP_REFUSED\n', 'host-inspection-unproved'], // Also emitted by older helpers.
    ['DIRECT_INSPECT_CHAP_PROJECTION_UNPROVED\n', 'chap-projection-unproved'],
    ['DIRECT_INSPECT_PPP_UNPROVED\n', 'ppp-unproved'],
    ['DIRECT_INSPECT_PIDFD_GETFD_EPERM\n', 'pidfd-getfd-eperm'],
    ['DIRECT_INSPECT_READBACK_UNPROVED\n', 'inspect-readback-unproved'],
]);
const reasons = new Set(frames.values());

module.exports = {
    reasonFromInspectionFrame: stderr => frames.get(stderr),
    isInspectionReason: reason => reasons.has(reason),
};