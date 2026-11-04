"""Inventory parameterization only. Kernel/SSH/systemd/physical facts MODELED."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
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

if __name__=='__main__': unittest.main()
