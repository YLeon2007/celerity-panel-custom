"""Internal fixed-profile effects extracted from pinned NodeOriginals; no authority constructor.
Generic preflight is not imported, replaced or weakened. Dedicated caller supplies real locks/checkpoint.
"""
import base64, fcntl, hashlib, json, os, re, stat, subprocess, time
from pathlib import Path
from contextlib import contextmanager


XRAY = '/usr/local/bin/xray'

MAX_FILE = 512 * 1024

MAX_BUNDLE = 8 * 1024 * 1024

CLEAN_ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C', 'HOME':'/root'}

SERVICE_KEYS = {'Id','LoadState','FragmentPath','DropInPaths','ActiveState','UnitFileState','Job','NeedDaemonReload'}

TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')


class Refusal(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique(pairs):
    value = {}
    for k, v in pairs:
        need(k not in value, 'DUPLICATE_JSON_RETAINED')
        value[k] = v
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False, 'INVALID_JSON_RETAINED'))


def profile_paths(profile):
    need(profile in ('xray-main','xray-bridge'), 'FOREIGN_PROFILE_RETAINED')
    name = 'xray' if profile == 'xray-main' else 'xray-bridge'
    return '/usr/local/etc/' + name + '/config.json', '/etc/systemd/system/' + name + '.service'


def service_name(profile):
    return 'xray.service' if profile == 'xray-main' else 'xray-bridge.service'


def runner_lock(profile):
    return '/var/lib/celerity/topology/fences/' + profile + '/lock'


def runner_journal(profile):
    return '/var/lib/celerity/topology/fences/' + profile + '/journal.json'


class Files:
    """Descriptor-walk all production ancestors, refusing links and foreign writes."""
    def __init__(self, fixture=None):
        self.fixture = fixture
        self.uid, self.gid = (fixture.uid, fixture.gid) if fixture else (0, 0)

    @contextmanager
    def opened(self, fixed, directory=False, write=False):
        path = Path(fixed)
        need(path.is_absolute() and '..' not in path.parts, 'UNSAFE_PATH_RETAINED')
        root = self.fixture.root if self.fixture else Path('/')
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.trusted(os.fstat(fd), directory=True)
            for i, part in enumerate(path.parts[1:]):
                isdir = directory or i < len(path.parts) - 2
                flags = (os.O_RDWR if write and not isdir else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
                if isdir:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                self.trusted(os.fstat(fd), directory=isdir, fixed=None if isdir else str(path))
            yield fd
        finally:
            os.close(fd)

    def trusted(self, info, directory=False, fixed=None):
        # Existing classic writers publish these root-owned fixed profile leaves
        # as 0666. Capture/restore their authentic metadata, never chmod it into a
        # different baseline. Ancestors, binaries, locks and caches stay strict.
        legacy = not directory and fixed in {p for profile in ('xray-main','xray-bridge') for p in profile_paths(profile)} and stat.S_IMODE(info.st_mode) == 0o666
        need(info.st_uid == self.uid and info.st_gid == self.gid and (not info.st_mode & 0o022 or legacy) and
             (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), 'UNTRUSTED_FILE_RETAINED')
        if not directory:
            need(info.st_nlink == 1, 'HARDLINK_RETAINED')

    def read(self, path, limit=MAX_BUNDLE):
        with self.opened(path) as fd:
            before = os.fstat(fd)
            need(before.st_size <= limit, 'BYTE_LIMIT_RETAINED')
            chunks, size = [], 0
            while True:
                part = os.read(fd, min(65536, limit + 1 - size))
                if not part:
                    break
                size += len(part)
                need(size <= limit, 'BYTE_LIMIT_RETAINED')
                chunks.append(part)
            raw = b''.join(chunks)
            attrs = {key:base64.b64encode(os.getxattr(fd, key)).decode() for key in sorted(os.listxattr(fd))}
            need(len(canonical(attrs)) <= 65536, 'XATTR_LIMIT_RETAINED')
            after = os.fstat(fd)
            fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
            need(all(getattr(before,k) == getattr(after,k) for k in fields), 'FILE_CHANGED_RETAINED')
            return raw, {'sha256':sha(raw), 'mode':stat.S_IMODE(after.st_mode),
                         'uid':after.st_uid,'gid':after.st_gid,'xattrs':attrs}

    def info(self, path):
        return self.read(path, MAX_FILE)[1]

    def read_json(self, path):
        return decode(self.read(path)[0])

    def absent(self, path):
        with self.opened(str(Path(path).parent), directory=True) as fd:
            try:
                os.stat(Path(path).name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False

    def private(self, path):
        with self.opened(path, directory=True) as fd:
            need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'PRIVATE_STORE_REQUIRED')

    def make_store(self):
        self.private(STATE)
        with self.opened(STATE, directory=True) as fd:
            try:
                os.mkdir('originals', mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            os.fsync(fd)
        self.private(STORE)

    def atomic(self, path, raw, metadata=None, expected=None, new=False):
        need(len(raw) <= MAX_BUNDLE, 'BYTE_LIMIT_RETAINED')
        parent, name = str(Path(path).parent), Path(path).name
        with self.opened(parent, directory=True) as directory:
            if new:
                need(self.absent(path), 'EXISTING_ORIGINALS_RETAINED')
            elif expected is not None:
                need(canonical(self.info(path)) == canonical(expected), 'CURRENT_FILE_DRIFT_RETAINED')
            fd = os.open(name + '.next', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as out:
                out.write(raw)
                if metadata:
                    need(metadata['uid'] == self.uid and metadata['gid'] == self.gid and
                         type(metadata['mode']) is int and (metadata['mode'] & 0o7022 == 0 or
                         path in {p for profile in ('xray-main','xray-bridge') for p in profile_paths(profile)} and metadata['mode'] == 0o666), 'UNSAFE_METADATA_RETAINED')
                    os.fchown(out.fileno(), metadata['uid'], metadata['gid'])
                    os.fchmod(out.fileno(), metadata['mode'])
                    for key, value in metadata['xattrs'].items():
                        os.setxattr(out.fileno(), key, base64.b64decode(value, validate=True))
                out.flush()
                os.fsync(out.fileno())
            # Under held writer exclusion, the independently accepted current file
            # is checked again immediately before replacing its directory entry.
            if expected is not None:
                need(canonical(self.info(path)) == canonical(expected), 'CURRENT_FILE_DRIFT_RETAINED')
            if new:
                # link gives no-overwrite publication even if a foreign root races.
                os.link(name + '.next', name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                os.unlink(name + '.next', dir_fd=directory)
            else:
                os.replace(name + '.next', name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)

    @contextmanager
    def lock(self, path):
        with self.opened(path, write=True) as fd:
            need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o600, 'UNSAFE_LOCK_RETAINED')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield fd
            with self.opened(path) as current:
                a, b = os.fstat(fd), os.fstat(current)
                need((a.st_dev,a.st_ino) == (b.st_dev,b.st_ino), 'LOCK_REPLACED_RETAINED')


def bounded_run(argv, *, data=None, locks=(), timeout=8, limit=MAX_BUNDLE):
    """Private anonymous bounded output; no secret files or unbounded PIPEs."""
    import resource
    out = os.memfd_create('c3-originals-private-out',os.MFD_CLOEXEC)
    err = os.memfd_create('c3-originals-private-err',os.MFD_CLOEXEC)
    try:
        def bound():
            resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
        result = subprocess.run(argv,input=data,stdin=subprocess.DEVNULL if data is None else None,
                                stdout=out,stderr=err,env=CLEAN_ENV,
                                pass_fds=tuple(locks),timeout=timeout,preexec_fn=bound)
        os.lseek(out,0,os.SEEK_SET)
        os.lseek(err,0,os.SEEK_SET)
        stdout, stderr = os.read(out,limit+1), os.read(err,limit+1)
        need(len(stdout) < limit and len(stderr) < limit, 'OUTPUT_LIMIT_RETAINED')
        return subprocess.CompletedProcess(argv,result.returncode,stdout,stderr)
    except (subprocess.SubprocessError,OSError):
        # TimeoutExpired embeds argv (rmu may include emails); never export it.
        raise Refusal('FINITE_COMMAND_UNKNOWN_RETAINED') from None
    finally:
        os.close(out)
        os.close(err)


class System:
    def unit(self, service):
        need(service in ('xray.service','xray-bridge.service'), 'FOREIGN_SERVICE_RETAINED')
        result = bounded_run(['/usr/bin/systemctl','show','--no-pager',
                      '--property=' + ','.join(sorted(SERVICE_KEYS)), '--', service],timeout=10,limit=16384)
        need(result.returncode == 0 and not result.stderr and len(result.stdout) <= 16384, 'SYSTEMD_UNCONFIRMED_RETAINED')
        return dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)

    def action(self, verb, service=None, locks=()):
        need((verb == 'daemon-reload' and service is None) or
             (verb in ('restart','stop','enable','disable') and service in ('xray.service','xray-bridge.service')),
             'FOREIGN_SYSTEMD_ACTION_RETAINED')
        args = ['/usr/bin/systemctl',verb] + (['--',service] if service else [])
        result = bounded_run(args,locks=locks,timeout=15,limit=65536)
        need(result.returncode == 0, 'SYSTEMD_ACTION_UNKNOWN_RETAINED')


class OriginalEffects:
    # Explicit wrapper context, TEST by default. Existing TEST callers retain
    # their exact check; the separate PROD-only holder declares its own context.
    execution_context = 'test.infograd.online'

    def effect(self, verb, service=None):
        self.checkpoint()
        self.system.action(verb,service,self.locks)
        self.checkpoint()
    def service(self, profile):
        value = self.system.unit(service_name(profile))
        need(set(value) == SERVICE_KEYS and value['Id'] == service_name(profile) and value['LoadState'] == 'loaded'
             and value['FragmentPath'] == profile_paths(profile)[1] and value['DropInPaths'] == ''
             and value['Job'] == '' and value['NeedDaemonReload'] == 'no' and value['ActiveState'] in ('active','inactive')
             and value['UnitFileState'] in ('enabled','disabled'), 'SERVICE_UNPROVEN_RETAINED')
        return value
    def rpc(self, args, data=None):
        deadline = self.deadline
        need(deadline is not None and deadline > time.monotonic(), 'RPC_DEADLINE_RETAINED')
        assert deadline is not None
        self.checkpoint()
        raw, info = self.fs.read(XRAY, 128 * 1024 * 1024)
        need(sha(raw) == self.accepted['xraySha256'] and info['mode'] & 0o111, 'XRAY_BINARY_PIN_DRIFT')
        executable = str(self.fixture.root / XRAY.lstrip('/')) if self.fixture else XRAY
        result = bounded_run([executable,'api',*args],data=data,locks=self.locks,
                             timeout=min(8, deadline-time.monotonic()))
        need(result.returncode == 0 and not result.stderr and len(result.stdout) <= MAX_BUNDLE, 'RUNTIME_RPC_UNCONFIRMED_RETAINED')
        self.checkpoint()
        return result.stdout
    def runtime_layout(self, raw, active):
        # Match the repository's exact fresh-empty bytes, not arbitrary JSON
        # lacking inbounds. Only a validated inactive service can use this path:
        # active config bytes alone cannot exclude RPC-only runtime users.
        if raw in (b'{}', b'{}\n') and active == 'inactive':
            return None, []
        config = decode(raw)
        # The classic reverse bridge generators intentionally have no inbound
        # section (nor management API). Recognize that bounded outbound-only
        # layout without normalizing or regenerating the captured file bytes.
        if isinstance(config, dict) and 'inbounds' not in config:
            reverse = config.get('reverse')
            bridges = reverse.get('bridges') if isinstance(reverse, dict) else None
            outbounds = config.get('outbounds')
            routing = config.get('routing')
            need(set(config) == {'log', 'reverse', 'outbounds', 'routing'}
                 and set(reverse or {}) == {'bridges'}
                 and isinstance(bridges, list) and 1 <= len(bridges) <= 64
                 and all(isinstance(b, dict) and set(b) == {'tag', 'domain'}
                         and isinstance(b['tag'], str) and TOKEN.fullmatch(b['tag'])
                         and isinstance(b['domain'], str) and b['domain'] for b in bridges)
                 and isinstance(outbounds, list) and 1 <= len(outbounds) <= 66
                 and all(isinstance(o, dict) and o.get('protocol') in
                         ('vless', 'vmess', 'freedom', 'blackhole') for o in outbounds)
                 and isinstance(routing, dict) and isinstance(routing.get('rules'), list),
                 'UNSUPPORTED_RUNTIME_LAYOUT_RETAINED')
            return None, []
        need(isinstance(config,dict) and isinstance(config.get('inbounds'),list) and len(config['inbounds']) <= 64,
             'UNSUPPORTED_RUNTIME_LAYOUT_RETAINED')
        targets = [i for i in config['inbounds'] if i.get('protocol') == 'vless']
        need(all(i.get('protocol') in ('vless','dokodemo-door') for i in config['inbounds']), 'UNSUPPORTED_RUNTIME_LAYOUT_RETAINED')
        need(not targets or active == 'active', 'INACTIVE_VLESS_RUNTIME_UNPROVEN_RETAINED')
        if not targets:
            return None, []
        api = [i for i in config['inbounds'] if i.get('tag') == 'API_INBOUND']
        need(len(api) == 1 and api[0].get('protocol') == 'dokodemo-door' and api[0].get('listen') == '127.0.0.1'
             and type(api[0].get('port')) is int and 1 <= api[0]['port'] <= 65535
             and config.get('api',{}).get('tag') == 'API' and 'HandlerService' in config['api'].get('services',[])
             and any(r.get('inboundTag') == ['API_INBOUND'] and r.get('outboundTag') == 'API'
                     for r in config.get('routing',{}).get('rules',[])), 'RUNTIME_API_REQUIRED_RETAINED')
        tags = [i.get('tag') for i in targets]
        need(all(isinstance(t,str) and TOKEN.fullmatch(t) for t in tags) and len(set(tags)) == len(tags), 'UNSUPPORTED_INBOUND_RETAINED')
        return '--server=127.0.0.1:' + str(api[0]['port']), targets
    def users(self, server, tag):
        response = decode(self.rpc(['inbounduser',server,'-tag='+tag]))
        need(isinstance(response,dict) and set(response) <= {'users'} and isinstance(response.get('users',[]),list), 'RUNTIME_USERS_UNPROVEN_RETAINED')
        users = []
        emails, ids = set(), set()
        for user in response.get('users',[]):
            account = user.get('account',{})
            email = user.get('email')
            ident = account.get('id')
            flow = account.get('flow','')
            need(set(user) <= {'email','level','account'} and user.get('level',0) == 0
                 and isinstance(email,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}',email)
                 and email not in emails and isinstance(ident,str)
                 and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',ident) and ident not in ids
                 and set(account) <= {'_TypedMessage_','id','flow'} and account.get('_TypedMessage_') == 'xray.proxy.vless.Account'
                 and flow in ('','xtls-rprx-vision'), 'UNSUPPORTED_RUNTIME_USER_RETAINED')
            emails.add(email)
            ids.add(ident)
            users.append({'email':email,'id':ident,'flow':flow,'level':0})
        need(len(users) <= 4096, 'RUNTIME_USER_LIMIT_RETAINED')
        return sorted(users, key=lambda u:u['email'])
    def runtime(self, raw, active):
        server, targets = self.runtime_layout(raw, active)
        return {'mode':'rpc' if targets else 'none',
                'inbounds':{i['tag']:self.users(server,i['tag']) for i in targets}}
    def snapshot(self, profile):
        before = self.service(profile)
        files = {}
        for name,path in zip(('config','unit'),profile_paths(profile)):
            raw, meta = self.fs.read(path, MAX_FILE)
            need(meta['mode'] & 0o7022 == 0 or meta['mode'] == 0o666, 'UNSAFE_METADATA_RETAINED')
            files[name] = {**meta,'data':base64.b64encode(raw).decode()}
        raw = base64.b64decode(files['config']['data'],validate=True)
        runtime = self.runtime(raw, before['ActiveState'])
        need(before == self.service(profile), 'SERVICE_CHANGED_RETAINED')
        for name,path in zip(('config','unit'),profile_paths(profile)):
            need(self.fs.info(path) == {k:v for k,v in files[name].items() if k != 'data'}, 'FILE_CHANGED_RETAINED')
        return {'files':files,'service':before,'runtime':runtime}
    def restore_runtime(self, profile, original):
        raw = base64.b64decode(original['files']['config']['data'],validate=True)
        expected = original['runtime']
        server, targets = self.runtime_layout(raw,original['service']['ActiveState'])
        need(set(expected['inbounds']) == {i['tag'] for i in targets}, 'RUNTIME_BUNDLE_DRIFT_RETAINED')
        if targets:
            additions = []
            for inbound in targets:
                tag = inbound['tag']
                current = self.users(server,tag)
                if current:
                    self.rpc(['rmu',server,'-tag='+tag,*[u['email'] for u in current]])
                need(self.users(server,tag) == [], 'RUNTIME_REMOVE_UNCONFIRMED_RETAINED')
                additions.append({**inbound,'settings':{**inbound.get('settings',{}),'clients':expected['inbounds'][tag]}})
            if any(expected['inbounds'].values()):
                self.rpc(['adu',server,'/dev/stdin'],canonical({'inbounds':additions}))
        need(self.runtime(raw,original['service']['ActiveState']) == expected, 'RUNTIME_RESTORE_READBACK_FAILED')

    def restore_profile(self, profile, original, current):
        """NodeOriginals._restore_held finite effects, guarded by caller checkpoint.
        No authority construction, journal changes, admission opening or replay.
        """
        self.effect('stop', service_name(profile))
        need(self.service(profile)['ActiveState'] == 'inactive', 'SERVICE_STOP_UNCONFIRMED_RETAINED')
        self.checkpoint()
        for name, path in zip(('config','unit'), profile_paths(profile)):
            saved = original['files'][name]
            self.checkpoint()
            self.fs.atomic(path,base64.b64decode(saved['data'],validate=True),saved,
                           expected=current['files'][name])
            self.checkpoint()
        self.effect('daemon-reload')
        target = original['service']
        if self.service(profile)['UnitFileState'] != target['UnitFileState']:
            self.effect('enable' if target['UnitFileState']=='enabled' else 'disable',service_name(profile))
        self.checkpoint()
        if target['ActiveState'] == 'active':
            self.effect('restart',service_name(profile))
        self.restore_runtime(profile,original)

    def terminal(self, profile, pin):
        path = runner_journal(profile)
        need(self.fs.absent(str(Path(path).with_name('journal.next'))), 'RUNNER_UNKNOWN_RETAINED')
        raw = self.fs.read(path,4*1024*1024)[0]
        need(sha(raw) == pin, 'RUNNER_HEAD_DRIFT_RETAINED')
        journal = decode(raw)
        need(set(journal) == {'version','bootId','nodeId','executionContext','head','generations'}
             and type(journal['version']) is int and journal['version'] == 2
             and journal['bootId'] == self.physical['bootId'] and journal['nodeId'] == self.physical['nodeId']
             and journal['executionContext'] == self.execution_context, 'RUNNER_IDENTITY_DRIFT_RETAINED')
        head = journal['head']
        need(isinstance(head,str) and TOKEN.fullmatch(head) and head in journal['generations'], 'RUNNER_HEAD_UNKNOWN_RETAINED')
        need(isinstance(journal['generations'],dict) and len(journal['generations']) <= 1024, 'RUNNER_UNKNOWN_RETAINED')
        for generation, record in journal['generations'].items():
            need(set(record) == {'binding','phase','commands','serviceState'}, 'RUNNER_UNKNOWN_RETAINED')
            binding = record['binding']
            need(all(isinstance(binding.get(k),str) and TOKEN.fullmatch(binding[k]) and binding[k] not in ('.','..')
                     for k in ('operationId','nodeId','backupId','attemptId','generation','predecessorGeneration'))
                 and isinstance(binding.get('candidateHash'),str) and re.fullmatch('sha256:[a-f0-9]{64}',binding['candidateHash']),
                 'RUNNER_BINDING_UNKNOWN_RETAINED')
            need(record['phase'] == 'closed' and record['binding']['generation'] == generation and
                 record['binding']['targetProfile'] == profile and record['binding']['nodeId'] == self.physical['nodeId']
                 and record['binding']['executionContext'] == self.execution_context and
                 all(c['state'] == 'completed' for c in record['commands'].values()), 'RUNNER_UNKNOWN_RETAINED')
            closes = [(cid,c) for cid,c in record['commands'].items() if c.get('command') == 'close']
            need(len(closes) == 1, 'RUNNER_TERMINAL_UNPROVEN_RETAINED')
            cid, close = closes[0]
            receipt = close['receipt']
            need(set(record['binding']) == {'operationId','nodeId','candidateHash','backupId','targetProfile',
                                           'executionContext','attemptId','generation','predecessorGeneration'}
                 and set(close) == {'state','command','receipt'}
                 and set(receipt) == {'ok','command',*record['binding'],'commandId','protocolVersion','completion',
                                      'phase','terminal','ownershipRetained','terminalOutcome','bootId','systemdJob',
                                      'serviceState','completedCommand'}
                 and receipt.get('terminal') is True and receipt.get('completedCommand') == 'close'
                 and receipt.get('terminalOutcome') in ('verified','rolledback','cancelled')
                 and ((receipt.get('systemdJob'),receipt.get('serviceState')) in
                      (('not-applicable','not-applicable'),('completed','active:running'),('completed','inactive:dead')))
                 and all(receipt.get(k) == v for k,v in record['binding'].items()) and
                 receipt.get('commandId') == cid and receipt.get('command') == 'close' and receipt.get('ok') is True
                 and type(receipt.get('protocolVersion')) is int and receipt.get('protocolVersion') == 2 and receipt.get('bootId') == self.physical['bootId']
                 and receipt.get('completion') == 'completed' and receipt.get('phase') == 'closed'
                 and receipt.get('ownershipRetained') is True, 'RUNNER_TERMINAL_UNPROVEN_RETAINED')
        # The current head must close one complete serial predecessor chain,
        # not an old terminal generation beside a hidden successor/fork.
        seen, generation = set(), head
        while generation != 'none':
            need(generation in journal['generations'] and generation not in seen, 'RUNNER_HEAD_UNKNOWN_RETAINED')
            seen.add(generation)
            generation = journal['generations'][generation]['binding']['predecessorGeneration']
        need(seen == set(journal['generations']), 'RUNNER_HEAD_UNKNOWN_RETAINED')
        return sha(raw)

