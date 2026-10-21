"""Offline ELF/runtime input capture. No target executable or privileged call."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('classic_runtime_inputs', HERE/'classic_runtime_inputs.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def elf(*, interpreter='/lib64/ld-test.so', needed=('libtest.so.1',)):
    names = b'\0' + b''.join(x.encode()+b'\0' for x in needed)
    dynamic = [(5, 0x400300), (10, len(names))]
    offset = 1
    for name in needed:
        dynamic.append((1, offset)); offset += len(name)+1
    dynamic.append((0, 0))
    raw = bytearray(1024)
    raw[:16] = b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0, len(raw), len(raw), 4096)
    interp = interpreter.encode()+b'\0'
    struct.pack_into('<IIQQQQQQ', raw, 120, 3, 4, 0x200, 0, 0, len(interp), len(interp), 1)
    raw[0x200:0x200+len(interp)] = interp
    struct.pack_into('<IIQQQQQQ', raw, 176, 2, 4, 0x240, 0, 0, len(dynamic)*16, len(dynamic)*16, 8)
    for i, pair in enumerate(dynamic): struct.pack_into('<QQ', raw, 0x240+i*16, *pair)
    raw[0x300:0x300+len(names)] = names
    return bytes(raw)


class RuntimeInputTests(unittest.TestCase):
    def test_static_elf_parser_reads_interpreter_and_needed(self):
        m=load()
        self.assertEqual(m.elf_requirements(elf()), ('/lib64/ld-test.so', ['libtest.so.1']))

    def test_malformed_foreign_elf_and_path_search_refuse(self):
        m=load()
        for raw in (b'bad', elf()[:99], elf(interpreter='relative'), elf(needed=('../escape',))):
            with self.subTest(size=len(raw)), self.assertRaises(m.Refusal): m.elf_requirements(raw)
        raw=bytearray(elf()); raw[4]=1
        with self.assertRaises(m.Refusal): m.elf_requirements(raw)
        raw=bytearray(elf()); struct.pack_into('<Q',raw,0x240,29)
        with self.assertRaises(m.Refusal): m.elf_requirements(raw)

    def test_capture_materializes_stdlib_and_explicit_library_closure(self):
        m=load()
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp); libs=p/'libs'; libs.mkdir(); std=p/'stdlib'; std.mkdir()
            (std/'os.py').write_text('fixture stdlib\n'); (std/'__pycache__').mkdir()
            (std/'__pycache__/os.pyc').write_bytes(b'not copied')
            # ELF shared object fixture has no interpreter or DT_NEEDED.
            shared=bytearray(elf(needed=())); struct.pack_into('<I',shared,120,0)
            (libs/'libtest.so.1').write_bytes(shared); (libs/'ld-test.so').write_bytes(shared)
            binary=p/'node'; binary.write_bytes(elf()); binary.chmod(0o755)
            result=m.capture(binary,binary,std,[libs],python_target='/usr/bin/python3')
            self.assertFalse(result['physicalAccepted']); self.assertEqual(result['kind'],'offline-runtime-inputs')
            entries={x['target']:x for x in result['files']}
            for target in ('/runtime/node','/usr/bin/python3','/usr/lib/python3.13/os.py','/lib64/ld-test.so','/lib/x86_64-linux-gnu/libtest.so.1'):
                self.assertIn(target,entries)
            self.assertFalse(any('.pyc' in x for x in entries))
            for value in entries.values(): self.assertEqual(value['sha256'],hashlib.sha256(Path(value['source']).read_bytes()).hexdigest())

    def test_missing_library_and_escaping_stdlib_symlink_refuse(self):
        m=load()
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp); libs=p/'libs'; libs.mkdir(); std=p/'stdlib'; std.mkdir()
            binary=p/'node'; binary.write_bytes(elf()); binary.chmod(0o755)
            with self.assertRaises(m.Refusal): m.capture(binary,binary,std,[libs])
            binary.write_bytes(b'not executable data'); (std/'escape.py').symlink_to(binary)
            with self.assertRaises(m.Refusal): m.capture(binary,binary,std,[libs])

    def test_no_target_execution_and_manifest_rejects_drift(self):
        m=load()
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp); binary=p/'would-execute'; marker=p/'effect'
            binary.write_text('#!/bin/sh\ntouch '+str(marker)+'\n'); binary.chmod(0o755)
            with self.assertRaises(m.Refusal): m.capture(binary,binary,p,[])
            self.assertFalse(marker.exists())
            candidate={'version':1,'kind':'offline-runtime-inputs','physicalAccepted':False,'files':[
                {'source':str(binary),'target':'/runtime/node','sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'executable':True}]}
            m.verify(candidate)
            binary.write_text('drift')
            with self.assertRaisesRegex(m.Refusal,'DRIFT'): m.verify(candidate)

    def test_runtime_target_collision_and_ambient_site_packages_refuse(self):
        m=load()
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp); std=p/'stdlib'; std.mkdir(); (std/'site-packages').mkdir()
            (std/'site-packages/ambient.py').write_text('not allowed')
            (std/'dist-packages').mkdir(); (std/'dist-packages/ambient.py').write_text('not allowed')
            (std/'sitecustomize.py').symlink_to(p/'absent-host-customization')
            (std/'usercustomize.py').write_text('host customization must not load')
            (std/'config-3.13-fixture').mkdir()
            (std/'config-3.13-fixture/libpython.so').symlink_to(p/'outside-dev-library')
            raw=bytearray(elf(needed=())); struct.pack_into('<I',raw,120,0)
            binary=p/'binary'; binary.write_bytes(raw); binary.chmod(0o755)
            out=m.capture(binary,binary,std,[])
            self.assertFalse(any('packages' in e['target'] or 'customize' in e['target'] or '/config-' in e['target'] for e in out['files']))
            with self.assertRaises(m.Refusal): m.capture(binary,binary,std,[],python_target='/runtime/node')


if __name__=='__main__': unittest.main()
