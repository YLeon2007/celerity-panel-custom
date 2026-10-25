#!/usr/bin/env python3
"""Narrow LOCAL harness regressions, NOT actual-app outcome substitutes."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class ReviewRepairTests(unittest.TestCase):
    def test_runner_dispatch_preserves_both_manifest_bytes_and_refuses_reuse(self):
        proof_dir = Path(os.environ['C3_REAL_EVIDENCE']) / 'harness-collision'
        proof_dir.mkdir(parents=True, exist_ok=False)
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'], prefix='runner-collision-') as tmp:
            out = Path(tmp) / 'evidence'
            out.mkdir()
            spec = importlib.util.spec_from_file_location('runner', ROOT / 'scripts/test-node-isolation/lifecycle_vnext_run.py')
            assert spec is not None and spec.loader is not None
            runner = importlib.util.module_from_spec(spec)
            patcher = mock.patch.dict(os.environ, C3_REAL_EVIDENCE=str(out))
            patcher.start()
            self.addCleanup(patcher.stop)
            spec.loader.exec_module(runner)
            # Tiny external processes through the REAL dispatch seam. Harness data only.
            script = "import os,pathlib,sys; pathlib.Path(os.environ['C3_REAL_EVIDENCE'],'executed-source-sha256.json').write_bytes(sys.argv[1].encode())"
            first_bytes, second_bytes = '{"harness-map":"original"}\n', '[[".env","harness-array"]]\n'
            first = runner.run('harness-map', [sys.executable, '-I', '-B', '-c', script, first_bytes])
            self.assertEqual(first['exit'], 0)
            candidates = list(out.rglob('executed-source-sha256.json'))
            self.assertEqual(len(candidates), 1)
            first_path = candidates[0]
            second = runner.run('harness-array', [sys.executable, '-I', '-B', '-c', script, second_bytes])
            self.assertEqual(second['exit'], 0)
            self.assertEqual(first_path.read_bytes(), first_bytes.encode(), 'SR2: later suite overwrote first manifest')
            candidates = list(out.rglob('executed-source-sha256.json'))
            self.assertEqual(len(candidates), 2)
            self.assertEqual({p.read_bytes() for p in candidates}, {first_bytes.encode(), second_bytes.encode()})
            before = {p: p.read_bytes() for p in out.rglob('*') if p.is_file()}
            with self.assertRaises(FileExistsError):
                runner.run('harness-map', [sys.executable, '-I', '-B', '-c', script, 'OVERWRITE'])
            with self.assertRaises(FileExistsError):
                runner.main()  # real entry refuses existing root before gateway/dispatch
            self.assertEqual({p: p.read_bytes() for p in out.rglob('*') if p.is_file()}, before)
            for record in [first, second]:
                self.assertEqual(record['sourceManifest']['sha256'], runner.sha(Path(record['sourceManifest']['path'])))
            empty = runner.run('harness-exit-zero-not-proof', [sys.executable, '-I', '-B', '-c', 'pass'], expected=1)
            self.assertEqual(empty['exit'], 0)
            self.assertFalse(empty['passed'], 'exit zero without named/count completion is not PASS')
            snapshots = {}
            for record in [first, second]:
                source = Path(record['sourceManifest']['path'])
                target = proof_dir / (record['name'] + '.json')
                target.write_bytes(source.read_bytes())
                snapshots[record['name']] = dict(path=str(target), sha256=runner.sha(target))
            (proof_dir / 'proof.json').write_text(json.dumps(dict(
                harnessOnly=True, actualAppOutcomes=False, records=[first, second], snapshots=snapshots,
                firstBytesSurvived=True, distinctManifests=True, rootReuseRefused=True,
                dispatchReuseRefused=True, existingBytesUnchanged=True, exitZeroWithoutCountRefused=not empty['passed']), indent=2))
            print('HARNESS_COLLISION_PASS: distinct bytes/hashes retained; root and suite reuse refused; exit zero is not proof')

    def test_classic_actual_fixture_early_failure_disposes_readonly_copy(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'], prefix='disposal-regression-') as tmp:
            # VM intercepts only harness test registration and injects failure at first
            # port allocation, AFTER the real tracked copy was made readonly. No app
            # imports, children, DB emulation, network requests or invented outcomes.
            script = r"""
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const file=path.resolve('tests/classicApplication.integration.test.js');
let body; const hooks=[]; const marker=Error('HARNESS_FAILURE_AFTER_READONLY');
const mod={exports:{}};
const req=name=>name==='node:test'?{test:(name,opts,fn)=>{body=fn;}}:name==='node:net'?{createServer:()=>{throw marker;}}:require(name);
const context={require:req,module:mod,__dirname:path.dirname(file),process,console,setTimeout,clearTimeout,Buffer};
// Preserve CommonJS main detection when the fixture is loaded as the test entry.
req.main=mod;
vm.runInNewContext(fs.readFileSync(file,'utf8'),context,{filename:file});
(async()=>{
 let fixture;
 try {
  await assert.rejects(body({after:fn=>hooks.push(fn)}),e=>e===marker);
  fixture=fs.readFileSync(path.join(process.env.C3_REAL_EVIDENCE,'last-fixture-path.txt'),'utf8').trim();
  const errors=[];for(const fn of hooks){try{await fn();}catch(e){errors.push(e);}}
  assert.equal(errors.length,0,'cleanup must succeed after injected setup failure');
  assert.equal(fs.existsSync(fixture),false,'readonly fixture tree survived registered cleanup');
  if(mod.exports.runFixtureCleanup){
   const order=[];const primary=Error('primary');
   await assert.rejects(mod.exports.runFixtureCleanup([async()=>{order.push('app');throw primary;},async()=>order.push('client'),async()=>order.push('peer'),async()=>order.push('tree')]),e=>e.errors[0]===primary);
   assert.deepEqual(order,['app','client','peer','tree'],'one cleanup failure must not skip later tasks');
  }
  console.log('HARNESS_DISPOSAL_PASS: actual fixture setup path; readonly copy removed; cleanup order/failure aggregation');
 } finally {
  // RED-only rescue of this exact owned disposable tree; never evidence/source.
  if(fixture && fs.existsSync(fixture)){
   function restore(d){const st=fs.lstatSync(d);if(st.isDirectory()&&!st.isSymbolicLink()){fs.chmodSync(d,st.mode|0o700);for(const e of fs.readdirSync(d))restore(path.join(d,e));}}
   restore(fixture);fs.rmSync(fixture,{recursive:true});
  }
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
"""
            env = dict(os.environ, C3_REAL_EVIDENCE=tmp)
            p = subprocess.run([os.environ['C3_NODE'], '-e', script], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout)
            self.assertIn('HARNESS_DISPOSAL_PASS', p.stdout)
            proof_dir = Path(os.environ['C3_REAL_EVIDENCE']) / 'harness-disposal'
            proof_dir.mkdir(parents=True, exist_ok=False)
            shutil.copyfile(Path(tmp) / 'fixture-cleanup.json', proof_dir / 'fixture-cleanup.json')
            (proof_dir / 'proof.json').write_text(json.dumps(dict(harnessOnly=True, actualAppOutcomes=False,
                injection='first port allocation after real tracked readonly copy',
                primarySetupFailureObserved=True, earlyRegisteredCleanupRan=True,
                orderedTasksContinueAfterError=True, cleanupFirstErrorRetained=True, stdout=p.stdout), indent=2))
            print(p.stdout, end='')


if __name__ == '__main__':
    unittest.main(verbosity=2)
