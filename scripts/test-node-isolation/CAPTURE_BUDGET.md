Capture-stage finite budget composition

coordinated_capture.py accepts a trusted, preselected integer lifetimeSeconds
in 80..600. Existing 80..120 configurations and the 120-second fixture default
are unchanged. This is a stage timeout, NOT a ROOT lease or an original-owner
authority. No environment/request selector or caller timestamp grants a hold.

Before starting a new capture stage, the trusted original caller must check its
existing original owner's remaining budget, reject a stage larger than that
remaining time (or 600 seconds), and reserve time for later phases. It must keep
enforcing the SAME original deadline independently across all children, including
reconnect/restart. Config validation alone cannot enforce a cross-process original
lease; an externally held owner/guard and its unchanged deadline are prerequisites.
A new child cannot renew the enclosing instance. Unknown instances cannot resume.

The native Coordinator fixes its deadline at construction; Channel instances use
that same deadline. CaptureChannel fixes its wire deadline on initial entry;
check/observe do not reset it. Live peer, membership, guard and config checks are
unchanged. An external original owner must still refuse expired activity even if
a later-born child's local stage deadline has not elapsed.

Only capture's configured upper bound changes. Restoration has its own 80..120
contract and must receive its independently preselected budget, never inherit a
larger capture lifetime. The Node consumer's successful finish now uses its
existing constructor-selected IO budget (default 15000ms), not an incidental
3000ms cap: native finish also performs fresh held checks. Per-request defaults,
failed-child disposal's 3000ms bound and all activation/COMMIT, ownership,
dispatch and handback predicates are unchanged. No installed config,
old acceptance pin or historical profile is updated by this change.

Focused tests: python3 -B -m unittest -v test_capture_budget
(run from scripts/test-node-isolation). The scaled-clock original-owner fixture
exercises unchanged Invocation.budget but is explicitly MODELED, not physical
ROOT authority. Its UDS codec test uses synthetic protocol state and real sockets.
The genuine local joined evidence is a separate acceptance artifact.
