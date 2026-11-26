"""Read-only, local HostMainSession.verify_runtime callback; no receiver/CLI.

The trusted caller owns the accepted host, snapshot, managed tag scope, phase
route plan and continuing writer fence. It must establish that the active API,
inbound protocols and static router correspond to the admitted MAIN (no hot
replacement of those objects). The file checks are not a readback of Xray's
memory. Our two endpoint samples and pidfd do not exclude other writers, prove
exclusive possession of a shared socket FD, or authenticate the gRPC peer.

Success witnesses the scoped VLESS *named email index* and only the selected
TestRoute contexts. It says nothing about anonymous accounts, UUID-validator
state, untested predicates, the dispatcher's default or actual client egress.
"""
import json
import os
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

from rebuildTransitMainSession import MainSnapshot, RUNTIME, XrayGeneration
from rebuildTransitMainWindow import (
    AgentWindow, INVOCATION, MAIN, MAX_MAIN, TAG, XRAY, XRAY_EXEC, XRAY_PROPS,
    MainImage, WindowError, _file_generation, _file_metadata, _generation, _state_fields,
    client_settings, parse_json, require,
)

PROOF = Path('/usr/local/libexec/celerity/rebuild-main-proof')
XRAY_BIN = Path('/usr/local/bin/xray')
VERSION = 'native-xray-main-proof/v1'
API_PORT = 61000
_PORT_HEX = f'{API_PORT:04X}'.encode('ascii')
_LOOPBACK_HEX = f'{int.from_bytes(bytes([127, 0, 0, 1]), sys.byteorder):08X}'.encode('ascii')
MAX_INBOUNDS, MAX_USERS, MAX_ROUTES = 16, 10_000, 32
MAX_INPUT = 2 << 20
RECEIPT_LIMIT = 4096
PROOF_TIMEOUT = 9  # Helper's own hard deadline: 8 s. Reserve local reap time.
SHOW_TIMEOUT = 4
PROC_TABLE_LIMIT = 8 << 20
PROC_FDS_LIMIT = 65_536
_PID_MAX = (1 << 31) - 1
_OBSERVING_THREAD = Path('/proc/thread-self')
_UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
_EMAIL = re.compile(r'[!-~]{1,254}')


class RouteCheck(NamedTuple):
    inbound_tag: str
    network: str
    target_port: int
    outbound_tag: str
    target_domain: str | None = None
    target_ip: str | None = None


def _need(ok):
    require(ok, RUNTIME)


def _canonical(obj, *names):
    # Go's config decoder also matches case-insensitive field aliases.
    folded = {name.casefold() for name in names}
    if type(obj) is not dict:
        raise WindowError(RUNTIME)
    _need(all(k in names or k.casefold() not in folded for k in obj))
    return obj


def _tag(value):
    return type(value) is str and TAG.fullmatch(value) is not None


def _plan(data, managed, routes):
    cfg = _canonical(parse_json(data.decode('utf-8')), 'inbounds', 'outbounds', 'api', 'routing', 'reverse')
    api = _canonical(cfg.get('api'), 'tag', 'services', 'listen')
    router = _canonical(cfg.get('routing'), 'domainStrategy', 'rules', 'balancers')
    services, api_tag = api.get('services'), api.get('tag')
    _need(_tag(api_tag) and 'listen' not in api and type(services) is list
          and all(type(s) is str for s in services)
          and {'HandlerService', 'RoutingService'} <= set(services))
    _need(router.get('domainStrategy', 'AsIs') == 'AsIs' and router.get('balancers', []) == [])
    rules = router.get('rules')
    if type(rules) is not list or not rules:
        raise WindowError(RUNTIME)
    for raw in rules:
        rule = _canonical(raw, 'type', 'ruleTag', 'inboundTag', 'outboundTag', 'balancerTag')
        _need(rule.get('type') == 'field' and _tag(rule.get('outboundTag')) and 'balancerTag' not in rule)
    # Require the dedicated first API dispatch shown in the stock profile;
    # do not send a proof to a configured proxy or an ordinary data inbound.
    _need({k: v for k, v in rules[0].items() if k != 'ruleTag'} == {
        'type': 'field', 'inboundTag': ['API_INBOUND'], 'outboundTag': api_tag,
    })
    _need('API_INBOUND' not in managed)
    outbounds = cfg.get('outbounds', [])
    reverse = _canonical(cfg.get('reverse', {}), 'portals', 'bridges')
    for definitions in (outbounds, reverse.get('portals', []), reverse.get('bridges', [])):
        if type(definitions) is not list:
            raise WindowError(RUNTIME)
        for raw in definitions:
            outbound = _canonical(raw, 'tag')
            _need(outbound.get('tag') != api_tag)

    settings = client_settings(cfg, managed)
    for inbound in cfg['inbounds']:
        _canonical(inbound, 'tag', 'protocol', 'settings')
    matches = [row for row in cfg['inbounds'] if row['tag'] == 'API_INBOUND']
    _need(len(matches) == 1 and type(matches[0].get('port')) is int and matches[0] == {
        'tag': 'API_INBOUND', 'listen': '127.0.0.1', 'port': API_PORT,
        'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'},
    })

    named, total = [], 0
    for tag in sorted(managed):
        scoped = settings[tag]
        _canonical(scoped, 'clients', 'flow')
        default_flow = scoped.get('flow', '')
        _need(default_flow in ('', 'xtls-rprx-vision'))
        users = []
        for row in scoped['clients']:
            _canonical(row, 'email', 'id', 'flow', 'level')
            email = row.get('email', '')
            if email == '':
                continue  # The helper cannot prove anything about this row.
            uuid, flow, level = row.get('id'), row.get('flow', ''), row.get('level', 0)
            _need(type(email) is str and _EMAIL.fullmatch(email) and type(uuid) is str
                  and _UUID.fullmatch(uuid) and flow in ('', 'xtls-rprx-vision')
                  and type(level) is int and 0 <= level <= 0xFFFFFFFF)
            total += 1
            _need(total <= MAX_USERS)
            users.append(dict(email=email, uuid=uuid, flow=flow or default_flow, level=level))
        named.append(dict(tag=tag, users=users))

    # v1 does not offer a users-only receipt. Missing/empty plans never turn
    # into successful skips. The native decoder also validates full syntax,
    # uniqueness (including effective VLESS UUID keys), and canonical IPs.
    if type(routes) is not tuple or not 0 < len(routes) <= MAX_ROUTES:
        raise WindowError(RUNTIME)
    contexts = []
    for route in routes:
        if type(route) is not RouteCheck:
            raise WindowError(RUNTIME)
        _need(_tag(route.inbound_tag) and route.inbound_tag in managed
              and route.network in ('tcp', 'udp') and _tag(route.outbound_tag)
              and type(route.target_port) is int and 0 < route.target_port <= 65535)
        context = dict(inboundTag=route.inbound_tag, network=route.network, targetPort=route.target_port)
        _need(route.target_domain is not None or route.target_ip is not None)
        for key, value, limit in (('targetDomain', route.target_domain, 253), ('targetIP', route.target_ip, 45)):
            if value is not None:
                _need(type(value) is str and 0 < len(value) <= limit and value.isascii())
                context[key] = value
        contexts.append(dict(context=context, outboundTag=route.outbound_tag))
    frame = json.dumps(dict(version=VERSION, namedInbounds=named, routes=contexts),
                       separators=(',', ':')).encode('ascii')
    _need(len(frame) <= MAX_INPUT)
    return frame, tuple(len(row['users']) for row in named)


def _receipt(raw, counts, routes):
    _need(type(raw) is bytes and 0 < len(raw) <= RECEIPT_LIMIT)
    reply = parse_json(raw.decode('utf-8'))
    _need(type(reply) is dict and reply.keys() == {'version', 'userScope', 'namedInbounds', 'routesVerified'}
          and reply['version'] == VERSION and reply['userScope'] == 'named-vless-email-index'
          and type(reply['routesVerified']) is int and reply['routesVerified'] == routes)
    rows = reply['namedInbounds']
    if type(rows) is not list or len(rows) != len(counts):
        raise WindowError(RUNTIME)
    for row, count in zip(rows, counts):
        _need(type(row) is dict and row.keys() == {'handlerCount', 'enumeratedNamed'}
              and all(type(v) is int and v == count for v in row.values()))


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    _need(remaining > 0)
    return remaining


def _exchange(argv, data, *, timeout, limit):
    """One child, exact stdin + EOF, bounded pipes; no shell or inherited env."""
    # A caller reaping this child elsewhere (including ignored SIGCHLD) can
    # make Popen report 0 on ECHILD rather than the original exit status.
    _need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
    deadline = time.monotonic() + timeout
    io_end = deadline - min(0.5, timeout / 2)
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True, env={'LC_ALL': 'C'}, cwd='/', bufsize=0)
    try:
        writer, reader, errors = child.stdin, child.stdout, child.stderr
        assert writer is not None and reader is not None and errors is not None  # PIPE above
        with writer, reader, errors, selectors.DefaultSelector() as streams:
            for pipe in (writer, reader, errors):
                os.set_blocking(pipe.fileno(), False)
            pending = memoryview(data)
            if pending:
                streams.register(writer, selectors.EVENT_WRITE, writer)
            else:
                writer.close()
            streams.register(reader, selectors.EVENT_READ, reader)
            streams.register(errors, selectors.EVENT_READ, errors)
            output = bytearray()
            while streams.get_map():
                events = streams.select(_remaining(io_end))
                for event, _ in events:
                    _remaining(io_end)
                    pipe = event.data
                    try:
                        if pipe is writer:
                            size = os.write(writer.fileno(), pending[:65536])
                            _need(size > 0)
                            pending = pending[size:]
                            if not pending:
                                streams.unregister(writer)
                                writer.close()
                            continue
                        block = os.read(pipe.fileno(), 1 if pipe is errors else limit + 1 - len(output))
                    except BlockingIOError:
                        continue
                    if not block:
                        streams.unregister(pipe)
                        pipe.close()
                    else:
                        _need(pipe is reader and len(output) + len(block) <= limit)
                        output.extend(block)
            _need(not pending and child.wait(timeout=_remaining(io_end)) == 0)
        _remaining(io_end)
        return bytes(output)
    finally:
        if child.poll() is None:
            try:
                child.kill()  # Only the child just created, never Xray or systemd.
            finally:
                child.wait(timeout=max(0, deadline - time.monotonic()))


def _bounded_read(path, limit):
    with path.open('rb') as file:
        raw = file.read(limit + 1)
    _need(len(raw) <= limit)
    return raw


def _listeners():
    # Include IPv6 (possibly dual stack) and non-loopback binds on this port:
    # any second LISTEN row or nonexact address fails, not only a second 127.0.0.1.
    rows = []
    for table, width, remote in (('tcp', 8, b'rem_address'), ('tcp6', 32, b'remote_address')):
        raw = _bounded_read(_OBSERVING_THREAD / 'net' / table, PROC_TABLE_LIMIT)
        lines = raw.splitlines()
        _need(raw.endswith(b'\n') and lines[0].split()[:4] == [b'sl', b'local_address', remote, b'st'])
        for line in lines[1:]:
            fields = line.split()
            _need(len(fields) >= 10)
            addr, sep, port = fields[1].partition(b':')
            _need(sep and len(addr) == width and len(port) == 4)
            if fields[3] == b'0A' and port == _PORT_HEX:
                inode = fields[9]
                _need(not rows and table == 'tcp' and addr == _LOOPBACK_HEX
                      and inode.isdigit() and int(inode) > 0)
                rows.append(inode)
    _need(len(rows) == 1)
    return rows[0]


def _id(info):
    return info.st_dev, info.st_ino


def _exec_identity(path, production):
    if production:
        # Trust only ordinary root-controlled install paths, not shell/PATH,
        # symlink aliases or directories replaceable by a non-root writer.
        for ancestor in path.parents:
            info = ancestor.lstat()
            _need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and not info.st_mode & 0o7022
          and (not production or info.st_uid == 0))
    return _file_generation(info), _file_metadata(info)


def _alive(pidfd):
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    _need(not poll.poll(0))


def _process(pid, pidfd, argv, xray, main_image, production):
    _alive(pidfd)
    root = Path('/proc') / str(pid)
    raw = _bounded_read(root / 'stat', 4096)
    proc_name, sep, suffix = raw.rpartition(b') ')
    fields = suffix.split()
    _need(proc_name.startswith(f'{pid} ('.encode('ascii')) and sep and len(fields) > 19
          and fields[0] not in (b'Z', b'X', b'x', b'T', b't') and fields[19].isdigit() and int(fields[19]) > 0)
    want = b'\0'.join(os.fsencode(arg) for arg in argv) + b'\0'
    _need(_bounded_read(root / 'cmdline', 4096) == want)
    exe = _exec_identity(xray, production)
    _need((root / 'exe').readlink() == xray)
    running = (root / 'exe').stat()
    _need((_file_generation(running), _file_metadata(running)) == exe)
    # Confirm that the process's root resolves the same file generation, not
    # a private mount hiding a different config behind the same argv spelling.
    cfg = (root / 'root' / Path(argv[-1]).relative_to('/')).stat()
    _need((_file_generation(cfg), _file_metadata(cfg)) == (main_image.generation, main_image.metadata))
    net_path = root / 'ns/net'
    net = _id(net_path.stat())
    our_net = _OBSERVING_THREAD / 'ns/net'
    _need(_id(our_net.stat()) == net)
    inode = _listeners()
    link = 'socket:[' + inode.decode('ascii') + ']'
    with os.scandir(root / 'fd') as fds:
        for i, fd in enumerate(fds):
            _need(i < PROC_FDS_LIMIT)
            try:
                if os.readlink(fd.path) == link:
                    break
            except FileNotFoundError:
                # A concurrent close is not a positive ownership witness.
                continue
        else:
            raise WindowError(RUNTIME)
    _need(_listeners() == inode and os.readlink(fd.path) == link and _id(net_path.stat()) == net
          and _id(our_net.stat()) == net)
    _alive(pidfd)
    return fields[19], exe, net, inode


class MainRuntimeObserver:
    """Call as verify_runtime(phase, MainSnapshot) -> True or WindowError.

    routes_for(phase, snapshot) is a bounded trusted plan selector, returning
    an immutable tuple of RouteCheck values for this phase. Neither it nor
    the constructor is a request decoder. The caller holds its independent
    authority/fence across the callback; no retry, fallback or repair here.
    It must also leave waits for the observer's own children to the observer.
    _fixture_paths and _fixture_show are trusted in-process test seams only.
    """

    def __init__(self, managed, routes_for, *, _fixture_paths=None, _fixture_show=None):
        _need(type(managed) in (set, frozenset) and 0 < len(managed) <= MAX_INBOUNDS
              and all(_tag(tag) for tag in managed) and callable(routes_for))
        self._managed, self._routes = frozenset(managed), routes_for
        self._production = _fixture_paths is None
        self._proof, self._xray, self._main = (PROOF, XRAY_BIN, MAIN) if self._production else map(Path, _fixture_paths)
        _need(all(path.is_absolute() and '..' not in path.parts and str(path).isascii()
                  and not any(c.isspace() or c in '{};' for c in str(path))
                  for path in (self._proof, self._xray, self._main)))
        _need(_fixture_show is None or (not self._production and callable(_fixture_show)))
        self._fixture_show = _fixture_show
        self._files = AgentWindow(None, main=self._main)

    def _unit(self, target):
        command = ['/usr/bin/systemctl', 'show', '--all', *('--property=' + k for k in XRAY_PROPS), '--', XRAY]
        raw = (_exchange(command, b'', timeout=SHOW_TIMEOUT, limit=16384).decode('utf-8')
               if self._fixture_show is None else self._fixture_show(command, SHOW_TIMEOUT))
        _need(type(raw) is str and raw.endswith('\n'))
        unit = _state_fields(raw, XRAY_PROPS, XRAY)
        _need(_generation(unit) and XrayGeneration(int(unit['MainPID']), unit['InvocationID']) == target)
        if self._production:
            _need(XRAY_EXEC.fullmatch(unit['ExecStart']))
        for option in ('-config', '-c'):
            argv = (str(self._xray), 'run', option, str(self._main))
            prefix = '{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) + ' ; ignore_errors=no ; '
            if re.fullmatch(re.escape(prefix) + r'[^{}]*\}', unit['ExecStart']):
                return unit, argv
        raise WindowError(RUNTIME)

    def _sample(self, snapshot, pidfd, unit):
        image = self._files.read_main()
        _need(image == snapshot.main and self._unit(snapshot.xray) == unit)
        return _process(snapshot.xray.pid, pidfd, unit[1], self._xray, image, self._production)

    def _observe(self, phase, snapshot):
        _need(type(phase) is str and phase in ('baseline', 'capture', 'restart', 'reconcile') and type(snapshot) is MainSnapshot
              and type(snapshot.main) is MainImage and type(snapshot.main.data) is bytes
              and 0 < len(snapshot.main.data) <= MAX_MAIN and type(snapshot.xray) is XrayGeneration
              and type(snapshot.xray.pid) is int and 0 < snapshot.xray.pid <= _PID_MAX
              and type(snapshot.xray.invocation_id) is str and INVOCATION.fullmatch(snapshot.xray.invocation_id))
        for values in (snapshot.main.metadata, snapshot.main.generation):
            _need(type(values) is tuple and len(values) == 3 and all(type(v) is int for v in values))
        routes = self._routes(phase, snapshot)
        frame, counts = _plan(snapshot.main.data, self._managed, routes)
        proof = _exec_identity(self._proof, self._production)
        unit = self._unit(snapshot.xray)
        pidfd = os.pidfd_open(snapshot.xray.pid)
        try:
            before = self._sample(snapshot, pidfd, unit)
            _need(_exec_identity(self._proof, self._production) == proof)
            reply = _exchange((str(self._proof),), frame, timeout=PROOF_TIMEOUT, limit=RECEIPT_LIMIT)
            _need(self._unit(snapshot.xray) == unit and self._sample(snapshot, pidfd, unit) == before
                  and _exec_identity(self._proof, self._production) == proof)
            _receipt(reply, counts, len(routes))
        finally:
            os.close(pidfd)

    def __call__(self, phase, snapshot):
        try:
            self._observe(phase, snapshot)
        except Exception:
            # Do not attach raw JSON/config/child/callback exceptions, even
            # as suppressed __context__ on the public failure.
            pass
        else:
            return True
        raise WindowError(RUNTIME)
