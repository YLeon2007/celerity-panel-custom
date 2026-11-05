"""Inventory parameterization only. Kernel/SSH/systemd/physical facts MODELED."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
import subprocess
import unittest
from unittest.mock import patch
import coordinated_capture as capture
import isolation as m
import node_originals as n
import physical_attestor as attestor
import shared_host as shared
import test_isolation as ti
import test_node_originals as tn

PATH = '/etc/celerity/topology-test-inventory.json'
def fixture():
    inventory = {'version':1,'profile':'accepted-test-v1','executionContext':{'target':'test','hostIdentity':'test.infograd.online'},
                 'sharedNodeId':'a'*23+'2','nodes':[]}
    for i in (1,2):
        inventory['nodes'].append({'nodeId':'a'*23+str(i),'endpoint':{'ip':f'10.204.11.{i}','port':2222,'username':'c3-test-runner'},
            'targetProfile':'xray-main' if i==1 else 'xray-bridge','physical':{'machineId':str(i)*32,
            'bootId':f'11111111-1111-4111-8111-{i:012d}','sshHostKeySha256':str(i)*64},
            'profiles':['xray-main'] if i==1 else ['xray-main','xray-bridge']})
    raw = n.canonical(inventory)
    return inventory,raw,hashlib.sha256(raw).hexdigest()

class InventoryTests(unittest.TestCase):
    def test_fresh_isolation_plan_requires_separate_root_policy_and_exact_identity(self):
        inventory,raw,digest = fixture()
        plan = ti.PlanTests().plan()
        pin = inventory['nodes'][0]
        plan.update(version=2,inventorySha256=digest,nodeId=pin['nodeId'],endpointIp=pin['endpoint']['ip'],
                    targetProfile=pin['targetProfile'],**pin['physical'])
        with patch.object(m,'secure_file',side_effect=lambda p:raw if str(p)==PATH else self.fail('unexpected read')):
            self.assertEqual(m.validate_plan(plan),plan)
            for field,value in [('endpointIp','10.204.11.99'),('machineId','f'*32),('sshHostKeySha256','f'*64),('inventorySha256','f'*64)]:
                with self.subTest(field=field),self.assertRaises(m.Refusal): m.validate_plan({**plan,field:value})
            with self.assertRaises(m.Refusal): m.validate_plan({**plan,'nodeId':inventory['sharedNodeId']})
        with patch.object(m,'secure_file',side_effect=FileNotFoundError),self.assertRaises(FileNotFoundError): m.validate_plan(plan)

    def test_fresh_inventory_schema_rejects_alias_empty_default_and_public_endpoints(self):
        self.assertTrue(hasattr(m,'validate_inventory'),'accepted inventory contract is missing')
        inventory,_,_ = fixture()
        self.assertEqual(m.validate_inventory(inventory),inventory)
        for fault in ('alias','empty','public','shared','key','profile'):
            value=copy.deepcopy(inventory)
            if fault=='alias': value['nodes'][1]['physical']['machineId']=value['nodes'][0]['physical']['machineId']
            if fault=='empty': value['nodes']=[]
            if fault=='public': value['nodes'][0]['endpoint']['ip']='8.8.8.8'
            if fault=='shared': value['sharedNodeId']='f'*24
            if fault=='key': value['nodes'][0]['physical']['sshHostKeySha256']='bad'
            if fault=='profile': value['nodes'][1]['profiles']=['xray-bridge']
            with self.subTest(fault=fault),self.assertRaises(m.Refusal): m.validate_inventory(value)

    def test_actual_originals_capture_uses_accepted_dual_profiles_and_retains_lost_guard(self):
        inventory,raw,digest=fixture(); pin=inventory['nodes'][1]
        with tn.DualFixture() as f:
            f.plan.update(version=2,inventorySha256=digest,nodeId=pin['nodeId'],endpointIp=pin['endpoint']['ip'],**pin['physical'])
            f.accepted.update(n.identity(f.engine)); f.put(n.ACCEPTED,n.canonical(f.accepted)); f.put(PATH,raw)
            f.path(n.runner_lock('xray-main')).unlink()
            writer=n.NodeOriginals(f.engine,m,fixture=f.fixture)
            self.assertEqual(writer.profiles,['xray-main','xray-bridge'])
            writer.capture()
            self.assertEqual(set(f.fs.read_json(n.BUNDLE)['profiles']),set(pin['profiles']))
            self.assertTrue(writer.preserved_profile('xray-main'))
            def read(path,directory=False):
                info=f.path(path).stat()
                return (b'' if directory else f.fs.read(path)[0]),SimpleNamespace(st_uid=0,st_gid=0,
                    st_mode=info.st_mode,st_nlink=info.st_nlink)
            durable=attestor.durable_originals(f.engine,m,read)
            self.assertEqual(durable['bundleSha256'],n.sha(f.path(n.BUNDLE).read_bytes()))
            # Loss of an independently captured *secondary* original must refuse
            # the ordinary observer; primary-profile hashes alone are not enough.
            bundle=f.fs.read_json(n.BUNDLE)
            del bundle['profiles']['xray-main']
            saved=f.path(n.BUNDLE).read_bytes(); f.put(n.BUNDLE,n.canonical(bundle))
            with self.assertRaisesRegex(RuntimeError,'ORIGINAL_BUNDLE_IDENTITY_DRIFT'):
                attestor.durable_originals(f.engine,m,read)
            f.put(n.BUNDLE,saved)
            f.engine.phase='lost'
            with self.assertRaises(RuntimeError): writer.checkpoint()
            self.assertTrue(f.path(n.BUNDLE).is_file()); self.assertEqual(f.system.events,[])

    def test_fresh_shared_plan_binds_accepted_machine_without_relaxing_backend_layout(self):
        from test_shared_host import plan as shared_plan
        # Reuse the existing exact host-freezer modeled fixture, not a new hold.
        inventory,raw,digest=fixture(); pin=inventory['nodes'][1]
        plan=shared_plan()
        plan.update(version=2,inventorySha256=digest,nodeId=pin['nodeId'],endpointIp=pin['endpoint']['ip'],**pin['physical'])
        plan['hostHold']['expected']['host']={k:plan[k] for k in ('machineId','bootId')}
        with patch.object(m,'secure_file',return_value=raw):
            self.assertEqual(shared.validate_plan(plan,m),plan)
            broken=copy.deepcopy(plan); broken['hostHold']['expected']['controls']=[]
            with self.assertRaises(m.Refusal): shared.validate_plan(broken,m)

    def test_capture_accepts_only_same_inventory_digest_and_same_owner_challenge(self):
        from capture_fixture import CaptureFixture
        inventory,raw,digest=fixture()
        with CaptureFixture() as f:
            config=copy.deepcopy(f.config)
            old=list(config['nodes'])
            chosen=[old[0],old[-1]]
            nodes={}
            owner=[]
            for source,pin in zip(chosen,inventory['nodes']):
                item=config['nodes'][source]
                original=next(p for p in config['ownerChallenge']['nodes'] if p['nodeId']==source)
                # Use the fixture's real Ed25519 public-key bytes, then accept
                # that independently fixed digest in the modeled root inventory.
                pin['physical']['sshHostKeySha256']=item['identity']['sshHostKeySha256']
                item['identity'].update(nodeId=pin['nodeId'],endpointIp=pin['endpoint']['ip'],targetProfile=pin['targetProfile'],**pin['physical'])
                item['profiles']=pin['profiles']; nodes[pin['nodeId']]=item
                original.update(nodeId=pin['nodeId'],targetProfile=pin['targetProfile'],endpoint=pin['endpoint'],
                    nodeIdentity={k:pin['physical'][k] for k in ('machineId','sshHostKeySha256')},bootId=pin['physical']['bootId'])
                owner.append(original)
            raw=n.canonical(inventory); digest=n.sha(raw)
            config.update(version=2,inventorySha256=digest,nodes=nodes)
            config['origin'].update({k:inventory['nodes'][1]['physical'][k] for k in ('machineId','bootId')})
            isolation_raw=Path(m.__file__).read_bytes()
            for item in nodes.values():
                item['identity']['inventorySha256']=digest
                item['files']['isolation']=n.sha(isolation_raw)
            config['ownerChallenge'].update(version=2,inventorySha256=digest,nodes=owner)
            config['ownerChallenge']['host']['guard']['planHash']=nodes[inventory['sharedNodeId']]['identity']['planHash']
            def trusted_read(path):
                if path==PATH: return raw
                if path==n.HELPER: return isolation_raw
                self.fail('unexpected installed input')
            with patch.object(capture,'trusted_read',side_effect=trusted_read):
                self.assertEqual(capture.validate(config),config)
                for node in nodes:
                    self.assertIn('c3-test-operator@'+nodes[node]['identity']['endpointIp'],capture.ssh_argv(config,node))
                broken=copy.deepcopy(config); broken['ownerChallenge']['inventorySha256']='f'*64
                with self.assertRaises(RuntimeError): capture.validate(broken)
                broken=copy.deepcopy(config); broken['origin']['machineId']='f'*32
                with self.assertRaisesRegex(RuntimeError,'COORDINATOR_SHARED_HOST_MISMATCH'): capture.validate(broken)

class HostInventoryTests(unittest.TestCase):
    # Exact failed show argv/stdout/stderr captured on BOTH hosts in wave61.
    TEMPLATE = 'apport-coredump-hook@.service'
    TEMPLATE_SHOW = ['/usr/bin/systemctl', 'show', '--no-pager',
        '--property=Id,LoadState,ActiveState,SubState,UnitFileState,ControlGroup,MainPID,Job,FragmentPath,DropInPaths,KillMode,Triggers,TriggeredBy,RuntimeDirectory,RuntimeDirectoryMode,RuntimeDirectoryPreserve,User,Group',
        '--', TEMPLATE]
    TEMPLATE_STDERR = ('Failed to get properties: Unit name apport-coredump-hook@.service '
                       'is neither a valid invocation ID nor unit name.\n')

    @contextmanager
    def host(self, units='', files='', shows=None, file_bytes=None, jobs=''):
        # Only the systemd/proc/filesystem observations are modeled. Exercise the
        # actual Host.run/unit/inventory/check_inventory and their refusal paths.
        shows = shows or {}
        file_bytes = file_bytes or {}
        def run(argv, **kwargs):
            self.assertEqual(argv[0], '/usr/bin/systemctl')
            self.assertEqual(kwargs, {'env': m.CLEAN_ENV, 'stdin': subprocess.DEVNULL,
                'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'timeout': 40})
            if argv[1] == 'show':
                if argv[-1] == self.TEMPLATE:
                    self.assertEqual(argv, self.TEMPLATE_SHOW)
                    return subprocess.CompletedProcess(argv, 1, b'', self.TEMPLATE_STDERR.encode())
                self.assertIn(argv[-1], shows, 'unexpected unit observation')
                reply = shows[argv[-1]]
                if isinstance(reply, subprocess.CompletedProcess):
                    return reply
            else:
                self.assertIn(argv[1], ('list-units', 'list-unit-files', 'list-jobs'))
                reply = {'list-units': units, 'list-unit-files': files, 'list-jobs': jobs}[argv[1]]
            return subprocess.CompletedProcess(argv, 0, reply.encode(), b'')
        def path(value):
            value = str(value)
            return SimpleNamespace(is_file=lambda: value in file_bytes, is_dir=lambda: False,
                                   read_bytes=lambda: file_bytes[value])
        with patch.object(m.subprocess, 'run', side_effect=run) as execute, \
             patch.object(m.pathlib, 'Path', side_effect=path), \
             patch.object(m.Host, 'physical', return_value={'modeled': True}), \
             patch.object(m.Host, 'processes', return_value=[]):
            yield m.Host(), execute

    def test_uninstantiated_template_file_is_diagnostic_not_a_live_unit(self):
        # The listing row is modeled; the failed show response above is captured.
        with self.host(files=self.TEMPLATE + ' static -\n') as (host, execute):
            inventory = host.inventory()
            self.assertEqual(inventory['units'], {})
            self.assertEqual(inventory['unitFileTemplates'], {self.TEMPLATE: ['static', '-']})
            self.assertEqual(inventory['unitFilePins'], {})
            self.assertIs(inventory['diagnosticOnly'], True)
            self.assertIs(inventory['notAuthority'], True)
            self.assertNotIn('authority', inventory)
            self.assertFalse(any(call.args[0][1] == 'show' for call in execute.call_args_list))
            with self.assertRaises(m.Refusal):
                m.validate_inventory(inventory)


    def test_concrete_instance_retains_template_fragment_and_dropin_pins(self):
        fragment = '/usr/lib/systemd/system/foo@.service'
        dropin = '/etc/systemd/system/foo@.service.d/10-preserve.conf'
        instance_dropin = '/etc/systemd/system/foo@bar.service.d/20-preserve.conf'
        contents = {fragment: b'[Service]\nExecStart=/bin/true\n',
                    dropin: b'[Service]\nRestart=no\n', instance_dropin: b'[Service]\nUser=nobody\n'}
        reply = ('Id=foo@bar.service\nLoadState=loaded\nActiveState=active\n'
                 f'FragmentPath={fragment}\nDropInPaths={dropin} {instance_dropin}\n')
        for source in ('loaded', 'file-only'):
            with self.subTest(source=source), self.host(
                    units='foo@bar.service loaded active running Foo\n' if source == 'loaded' else '',
                    files='foo@.service static -\nfoo@bar.service enabled enabled\n',
                    shows={'foo@bar.service': reply}, file_bytes=contents) as (host, execute):
                inventory = host.inventory()
                self.assertEqual(inventory['units'], {'foo@bar.service': {
                    'Id': 'foo@bar.service', 'LoadState': 'loaded', 'ActiveState': 'active',
                    'FragmentPath': fragment, 'DropInPaths': dropin + ' ' + instance_dropin}})
                self.assertEqual(inventory['unitFileTemplates'], {'foo@.service': ['static', '-']})
                self.assertEqual(inventory['unitFilePins'], {p: m.digest(raw) for p, raw in contents.items()})
                self.assertEqual([c.args[0][-1] for c in execute.call_args_list if c.args[0][1] == 'show'],
                                 ['foo@bar.service'])

    def test_uninstantiated_socket_and_timer_files_do_not_fabricate_runtime_states(self):
        with self.host(files='foo@.socket disabled enabled\nfoo@.timer disabled -\n') as (host, _):
            inventory = host.inventory()
            self.assertEqual(inventory['units'], {})
            self.assertEqual(inventory['unitFileTemplates'], {
                'foo@.socket': ['disabled', 'enabled'], 'foo@.timer': ['disabled', '-']})

    def test_concrete_unit_show_failure_is_still_fatal(self):
        for name in ('broken.service', 'foo@bar.service'):
            with self.subTest(name=name), self.host(files=self.TEMPLATE + ' static -\n' + name + ' enabled -\n',
                    shows={name: subprocess.CompletedProcess([], 5, b'', b'arbitrary failure\n')}) as (host, execute):
                with self.assertRaisesRegex(m.Refusal, '^HOST_COMMAND_FAILED$'):
                    host.inventory()
                self.assertEqual(execute.call_args_list[-1].args[0][-1], name)

    def test_loaded_template_name_is_not_hidden_by_file_template_classification(self):
        with self.host(units=self.TEMPLATE + ' loaded active running Unexpected\n',
                       files=self.TEMPLATE + ' static -\n') as (host, execute):
            with self.assertRaisesRegex(m.Refusal, '^HOST_COMMAND_FAILED$'):
                host.inventory()
            self.assertEqual(execute.call_args_list[-1].args[0], self.TEMPLATE_SHOW)

    def test_malformed_name_handling_is_unchanged(self):
        # Invalid UNIT names remain ignored; malformed names admitted by the
        # existing grammar must still reach show and fail, not become templates.
        invalid = ('../bad@.service', 'bad/name@.service', 'bad@.service;touch', r'bad\xZZ@.service')
        with self.host(files=''.join(name + ' static -\n' for name in invalid)) as (host, execute):
            inventory = host.inventory()
            self.assertEqual(inventory['units'], {})
            self.assertEqual(inventory['unitFileTemplates'], {})
            self.assertFalse(any(c.args[0][1] == 'show' for c in execute.call_args_list))
        for name in ('bad@@.service', 'bad@bar@.timer', 'bad@.scope'):
            with self.subTest(name=name), self.host(files=name + ' static -\n',
                    shows={name: subprocess.CompletedProcess([], 1, b'', b'invalid unit name\n')}) as (host, _):
                with self.assertRaisesRegex(m.Refusal, '^HOST_COMMAND_FAILED$'):
                    host.inventory()

    def test_concrete_ssh_instance_still_requires_review(self):
        with self.host(files='sshd@.service static -\nsshd@bar.service enabled -\n',
                       shows={'sshd@bar.service': 'LoadState=loaded\nActiveState=active\n'}) as (host, _):
            with self.assertRaisesRegex(m.Refusal, '^UNREVIEWED_ACTIVATION_UNIT$'):
                host.check_inventory(ti.PlanTests().plan())

    def test_concrete_instance_template_file_pins_are_still_required_by_consumer(self):
        plan = ti.PlanTests().plan()
        fragment = '/usr/lib/systemd/system/foo@.service'
        raw = b'[Service]\nExecStart=/bin/true\n'
        shows = {u: 'LoadState=not-found\nActiveState=inactive\n' for u in plan['isolateUnits']}
        shows['foo@bar.service'] = f'LoadState=loaded\nActiveState=active\nFragmentPath={fragment}\n'
        with self.host(files='foo@.service static -\nfoo@bar.service enabled -\n',
                       shows=shows, file_bytes={fragment: raw}) as (host, _):
            with self.assertRaisesRegex(m.Refusal, '^UNREVIEWED_UNIT_FILE$'):
                host.check_inventory(plan)
            plan['unitFilePins'][fragment] = m.digest(raw)
            self.assertIn('foo@bar.service', host.check_inventory(plan)['units'])
            plan['unitFilePins'][fragment] = '0' * 64
            with self.assertRaisesRegex(m.Refusal, '^UNREVIEWED_UNIT_FILE$'):
                host.check_inventory(plan)

    def test_inventory_list_command_failures_are_not_swallowed(self):
        for command in ('list-units', 'list-unit-files', 'list-jobs'):
            with self.subTest(command=command), self.host() as (host, _):
                def run(argv, **kwargs):
                    return subprocess.CompletedProcess(argv, 1 if argv[1] == command else 0,
                                                       b'', b'arbitrary command failure\n')
                with patch.object(m.subprocess, 'run', side_effect=run), \
                     self.assertRaisesRegex(m.Refusal, '^HOST_COMMAND_FAILED$'):
                    host.inventory()


if __name__=='__main__': unittest.main()
