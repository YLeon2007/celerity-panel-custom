# Offline Xray SOCKS handoff regression

From the repository root, run as an ordinary user on Linux amd64 with system
Python 3.11+, `ldd`, iproute2 (`ip`, `ss`), and bubblewrap with rootless user and
network namespace support:

```sh
/usr/bin/python3 -I -B -S scripts/rebuild-relay-real-handoff/run.py /path/to/cached/xray-26.11.9
# Optional legacy comparison:
/usr/bin/python3 -I -B -S scripts/rebuild-relay-real-handoff/run.py --version 26.3.27 /path/to/cached/xray-26.3.27
```

Use ordinary readable local copies owned by the invoking user (the launcher uses
`O_NOATIME`). The launcher never downloads anything. It checks the executable
SHA-256 before launch and again in the sandbox, then runs `xray version` there.
The `26.11.9` pin is the one in [`retired-reverse-xray/verify.py`](../retired-reverse-xray/verify.py),
not a claim of upstream signature verification.

Bubblewrap starts a fresh rootless sandbox with an isolated PID and network
namespace, only `lo` up, and no IPv4 or IPv6 default route. The launcher clears
the environment and mounts only the chosen Xray executable, the test and product
helper sources, and the needed local runtime files. It does not mount host
configuration, service sockets, the repository tree or other Xray inputs. The
only config is generated on private tmpfs: a loopback SOCKS inbound, `noauth`,
`udp: true`, and a `blackhole` outbound. Namespace/setup failures are fatal;
there is no host-network fallback.

The test checks the exact PID-owned TCP listener and the absence of fixed UDP on
26.11.9. An independent SOCKS5 exchange checks that UDP ASSOCIATE returns a
nonzero, distinct loopback UDP endpoint owned by the same Xray PID, and that the
control connection and ephemeral UDP socket disappear after close. The legacy
run expects the fixed UDP tuple to exist at startup and remain after close.

By default the test also calls `sock_rows()` and `verify_socks_handoff()` from
`src/services/rebuildRelayDirectHost.py` on the real listener. It observes the
actual TCP socket without mocking network I/O: the 26.11.9 path must connect once
and close the descriptor before returning; the legacy fixed-bind path must not
connect. The run checks socket state again, reaps Xray and checks the listeners
are gone before printing `pass`. `--core-only` explicitly omits the product
helper and is reported as a separate mode. This fixture does not send UDP
traffic or test systemd, TPROXY, PPP, installation or an operational deployment.
