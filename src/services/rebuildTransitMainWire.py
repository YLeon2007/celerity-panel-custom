"""One held HostMainSession over an authenticated, lockstep NDJSON channel.

The embedding caller owns peer authentication, durable intent and artifact
pins. No CLI, connection establishment, replay, or compensation lives here.
"""
import base64
from contextlib import ExitStack
import hashlib
import hmac
import json
import math
import os
import re
import select
from threading import Lock
import time

from rebuildTransitMainWindow import MAIN_DRIFT, MAX_MAIN, WindowError, require

REQUEST = 'REBUILD_MAIN_WIRE_REQUEST'
PHASE = 'REBUILD_MAIN_WIRE_PHASE'
EOF = 'REBUILD_MAIN_WIRE_EOF'
LIMIT = 'REBUILD_MAIN_WIRE_LIMIT'
SETTLEMENT = 'REBUILD_MAIN_WIRE_SETTLEMENT'
UNKNOWN = 'REBUILD_MAIN_WIRE_UNCONFIRMED'
# Exact allowlist: do not let an injected WindowError, manager output, path,
# request data, or an unexpected exception message escape on a refusal.
_REASONS = frozenset({
    REQUEST, PHASE, EOF, LIMIT, SETTLEMENT, MAIN_DRIFT,
    'REBUILD_DIRECT_RECEIPT_UNPROVED', 'REBUILD_DIRECT_RECEIPT_LAYOUT_UNSUPPORTED',
    'REBUILD_DIRECT_RECEIPT_REQUIRES_NETWORK', 'REBUILD_DIRECT_RECEIPT_MAIN_DRIFT',
    'REBUILD_DIRECT_RECEIPT_WRITER_EXCLUSION_UNPROVED', 'REBUILD_DIRECT_RECEIPT_FINAL_UNPROVED',
    'REBUILD_DIRECT_RECEIPT_WRITE_UNCONFIRMED',
    'REBUILD_MAIN_LOCK_UNPROVED', 'REBUILD_MAIN_AUTHORITY_UNPROVED',
    'REBUILD_MAIN_RUNTIME_UNPROVED', 'REBUILD_MAIN_SESSION_STATE',
    'REBUILD_MAIN_PUBLICATION_UNCONFIRMED', 'REBUILD_MAIN_RESTART_UNCONFIRMED',
    'REBUILD_AGENT_EXCLUSION_UNPROVED', 'REBUILD_AGENT_MANAGED_PROFILE_UNPROVED',
    'REBUILD_AGENT_WINDOW_STATE', 'REBUILD_AGENT_STOP_UNCONFIRMED',
    'REBUILD_AGENT_START_UNCONFIRMED', 'REBUILD_AGENT_RECONCILE_UNPROVED',
})
_FIELDS = {
    'read': (), 'stop': (), 'capture': ('target',),
    'publish': ('beforeSha256', 'desiredSha256'),
    'restart': (), 'start': (), 'reconcile': (), 'verify': (),
}
_SHA256 = re.compile(r'[0-9a-f]{64}')
_SMALL_FRAME = 1024  # including LF
_B64_MAX = 4 * ((MAX_MAIN + 2) // 3)
_CAPTURE_FRAME = _B64_MAX + _SMALL_FRAME
_MAX_REPLY = 2 * _B64_MAX + _SMALL_FRAME
_CHUNK = 65536


def _json(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _image(image):
    return {'data': _b64(image.data), 'metadata': list(image.metadata),
            'generation': [str(part) for part in image.generation]}


def _snapshot(snapshot):
    return {**_image(snapshot.main), 'xray': list(snapshot.xray)}


def _pairs(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), REQUEST)
    return result


def _reject_number(_):
    # All admitted request values are strings.
    raise WindowError(REQUEST)


def _request(line, expected):
    try:
        obj = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs,
                         parse_int=_reject_number, parse_float=_reject_number, parse_constant=_reject_number)
    except (ValueError, RecursionError):
        raise WindowError(REQUEST) from None
    if type(obj) is not dict or type(action := obj.get('action')) is not str or action not in _FIELDS:
        raise WindowError(REQUEST)
    fields = _FIELDS[action]
    require(obj.keys() == {'action', *fields} and all(type(obj[key]) is str for key in fields), REQUEST)
    require(action == expected, PHASE)
    return obj


def _target(value):
    require(len(value) <= _B64_MAX, LIMIT)
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError:
        raise WindowError(REQUEST) from None
    require(len(data) <= MAX_MAIN, LIMIT)
    require(data and _b64(data) == value, REQUEST)
    return data


def _digest_matches(supplied, data):
    return hmac.compare_digest(supplied, hashlib.sha256(data).hexdigest())


class _TransportLost(Exception):
    """No further output is safe (expired deadline or broken transport)."""


class _Channel:
    def __init__(self, read_fd, write_fd, deadline):
        self.read_fd = read_fd
        self.write_fd = write_fd
        self.deadline = deadline
        self.reader = select.poll()
        self.reader.register(read_fd, select.POLLIN)
        self.writer = select.poll()
        self.writer.register(write_fd, select.POLLOUT)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _TransportLost()
        return remaining

    def _wait(self, poller):
        # Round up for poll(2), then enforce strict monotonic < on wakeup.
        try:
            while not poller.poll(math.ceil(1000 * min(1.0, self.remaining()))):
                pass
        except OSError:
            raise _TransportLost() from None
        self.remaining()

    def _read(self, size):
        try:
            return os.read(self.read_fd, size)
        except BlockingIOError:
            return None
        except OSError:
            raise _TransportLost() from None

    def _read_wait(self, size):
        while True:
            self._wait(self.reader)
            data = self._read(size)
            if data is not None:
                return data

    def _peer_waiting(self):
        self.remaining()
        pending = self._read(1)
        require(pending != b'', EOF)
        require(pending is None, PHASE)
        self.remaining()

    def request(self, action):
        limit = _CAPTURE_FRAME if action == 'capture' else _SMALL_FRAME
        line = bytearray()
        while len(line) < limit:
            chunk = self._read_wait(min(_CHUNK, limit - len(line)))
            require(chunk, EOF)
            end = chunk.find(b'\n')
            if end < 0:
                line.extend(chunk)
                continue
            require(end == len(chunk) - 1, PHASE)
            line.extend(chunk[:end])
            result = _request(line, action)
            # The caller must wait for this phase's reply, including verify.
            # Check already available bytes/EOF before dispatch, without waiting.
            self._peer_waiting()
            return result
        raise WindowError(LIMIT)

    def send(self, reply):
        self.remaining()
        data = memoryview(_json(reply) + b'\n')
        require(len(data) <= _MAX_REPLY, LIMIT)
        while data:
            self._wait(self.writer)
            try:
                size = os.write(self.write_fd, data)
            except BlockingIOError:
                continue
            except OSError:
                raise _TransportLost() from None
            if not size:
                raise _TransportLost()
            data = data[size:]
        self.remaining()

    def ok(self, value=None):
        self._peer_waiting()
        self.send({'ok': True, 'value': value})

    def terminal_eof(self):
        require(self._read_wait(1) == b'', PHASE)
        self.remaining()


class HostMainWire:
    """Single-use receiver. Call serve(read_fd, write_fd, deadline=...) once.

    FDs are exclusively borrowed raw pipes/stream descriptors (no buffered
    peers on this side). The embedder closes them and propagates the returned
    exit status. The single absolute time.monotonic() deadline is supplied to
    session_factory(deadline) and all optional hooks. The trusted factory and
    runner must clip native waits; the receiver cannot safely interrupt
    synchronous host work, but never acknowledges a late result. Read and
    capture hooks take (session, observation, deadline) and must return True
    before stop or publish respectively. Settlement hooks take (MainSnapshot,
    deadline), must return True, and are followed by a fresh exact read on
    the original held session before acknowledgement.

    Requests/replies are one UTF-8 JSON object per LF-terminated line. Request
    keys are action only, except capture adds target (canonical base64) and
    publish adds beforeSha256 and desiredSha256 (lowercase hex). Capture yields
    {before: MainImage wire object, desired: base64}. The panel must authenticate
    and reopen the bound artifacts and hash their exact plaintext: before is
    compact JSON with keys data, metadata, generation in that order (no LF),
    and desired is raw MAIN bytes. Hashes only select the captured pair in this
    live session; the native publication still checks the exact file preimage.
    Read/restart/reconcile/verify yield snapshots with an extra xray pair;
    publish yields a MainImage, and stop/start yield null. Generation integers
    are decimal strings. The caller must wait for each acknowledgement before
    sending the next request, then close its input only after verify's reply.
    Only terminal input EOF followed by successful session disposal returns 0.
    A refusal or missing acknowledgement is not no-effect or replay authority.
    """

    def __init__(self, session_factory, *, on_read=None, on_capture=None, on_reconcile=None, on_verify=None):
        self._factory = session_factory
        self._on_read = on_read
        self._on_capture = on_capture
        self._on_reconcile = on_reconcile
        self._on_verify = on_verify
        self._admission = Lock()

    def _settle(self, channel, session, callback, snapshot):
        channel.remaining()
        if callback is not None:
            channel._peer_waiting()
            require(callback(snapshot, channel.deadline) is True, SETTLEMENT)
            channel.remaining()
            require(session.read() == snapshot, MAIN_DRIFT)
        channel.ok(_snapshot(snapshot))

    def _exchange(self, channel, session):
        baseline = session.read()
        if self._on_read is not None:
            require(self._on_read(session, baseline, channel.deadline) is True, SETTLEMENT)
        channel.ok(_snapshot(baseline))

        channel.request('stop')
        session.stop()
        channel.ok()

        target = _target(channel.request('capture')['target'])
        channel.remaining()
        capture = session.capture(baseline, target)
        if self._on_capture is not None:
            require(self._on_capture(session, capture, channel.deadline) is True, SETTLEMENT)
        del baseline, target
        before = _image(capture.before)
        channel.ok({'before': before, 'desired': _b64(capture.desired)})

        request = channel.request('publish')
        before_hash, desired_hash = request['beforeSha256'], request['desiredSha256']
        require(_SHA256.fullmatch(before_hash) and _SHA256.fullmatch(desired_hash), REQUEST)
        require(_digest_matches(before_hash, _json(before)) and _digest_matches(desired_hash, capture.desired), MAIN_DRIFT)
        channel.remaining()
        channel.ok(_image(session.publish(capture.before, capture.desired)))
        del before, capture

        channel.request('restart')
        channel.ok(_snapshot(session.restart()))
        channel.request('start')
        session.start()
        channel.ok()
        channel.request('reconcile')
        reconciled = session.reconcile()
        self._settle(channel, session, self._on_reconcile, reconciled)
        channel.request('verify')
        verified = session.read()
        require(verified == reconciled, MAIN_DRIFT)
        self._settle(channel, session, self._on_verify, verified)
        channel.terminal_eof()

    def serve(self, read_fd, write_fd, *, deadline):
        if not self._admission.acquire(blocking=False):  # deliberately never reopened
            return 1
        try:
            if not math.isfinite(deadline):
                return 1
            with ExitStack() as restore:
                for fd in dict.fromkeys((read_fd, write_fd)):
                    if os.get_blocking(fd):
                        os.set_blocking(fd, False)
                        restore.callback(os.set_blocking, fd, True)
                channel = _Channel(read_fd, write_fd, deadline)
                try:
                    channel.request('read')
                    with self._factory(deadline) as session:
                        channel.remaining()
                        self._exchange(channel, session)
                except _TransportLost:
                    return 1
                except Exception as error:
                    code = error.code if isinstance(error, WindowError) else None
                    channel.send({'ok': False, 'reason': code if type(code) is str and code in _REASONS else UNKNOWN})
                    return 1
            channel.remaining()
            return 0
        except Exception:
            # Broken/refused output or local disposal failure is not completion.
            return 1
