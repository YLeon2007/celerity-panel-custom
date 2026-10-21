#!/usr/bin/python3
"""Offline x86-64 runtime input proposal; never executes an inspected binary.

Explicit Node/Python/stdlib/library inputs only. This captures bytes, NOT live
resource authority or installed ownership/mount/capability acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

MAX_FILE = 256*1024*1024


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value: raise Refusal(code)


def elf_requirements(raw):
    """Parse bounded ELF64 little-endian x86-64 program/dynamic headers only."""
    need(len(raw)>=64 and raw[:7]==b'\x7fELF\x02\x01\x01', 'SUPPORTED_ELF64_REQUIRED')
    h=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
    need(h[0] in (2,3) and h[1]==62 and h[2]==1 and h[7]==64 and h[8]==56 and 0<h[9]<=512,
         'SUPPORTED_ELF64_REQUIRED')
    off,count=h[4],h[9]
    need(off>=64 and off+count*56<=len(raw), 'ELF_HEADERS_REQUIRED')
    headers=[struct.unpack_from('<IIQQQQQQ',raw,off+i*56) for i in range(count)]
    for entry in headers:
        need(entry[2]+entry[5]<=len(raw), 'ELF_SEGMENT_BOUNDS')
    interps=[x for x in headers if x[0]==3]; dynamics=[x for x in headers if x[0]==2]
    need(len(interps)<=1 and len(dynamics)<=1,'ELF_SEGMENT_DUPLICATE')
    interpreter=None
    if interps:
        x=interps[0]; data=raw[x[2]:x[2]+x[5]]
        need(1<len(data)<=4096 and data[-1:]==b'\0' and b'\0' not in data[:-1], 'ELF_INTERPRETER_REQUIRED')
        try: interpreter=data[:-1].decode('ascii')
        except UnicodeError: raise Refusal('ELF_INTERPRETER_REQUIRED') from None
        need(interpreter.startswith('/') and str(Path(interpreter))==interpreter and
             '..' not in Path(interpreter).parts, 'ELF_INTERPRETER_REQUIRED')
    if not dynamics: return interpreter,[]
    x=dynamics[0]; need(x[5]%16==0,'ELF_DYNAMIC_BOUNDS')
    tags={}; ended=False
    for at in range(x[2],x[2]+x[5],16):
        tag,value=struct.unpack_from('<QQ',raw,at)
        if tag==0: ended=True; break
        need(tag not in (15,29), 'ELF_CUSTOM_SEARCH_PATH_FORBIDDEN')
        tags.setdefault(tag,[]).append(value)
    need(ended,'ELF_DYNAMIC_TERMINATOR_REQUIRED')
    if 1 not in tags: return interpreter,[]
    need(len(tags.get(5,[]))==len(tags.get(10,[]))==1,'ELF_STRING_TABLE_REQUIRED')
    address,size=tags[5][0],tags[10][0]
    loads=[x for x in headers if x[0]==1 and x[3]<=address and address+size<=x[3]+x[5]]
    need(len(loads)==1 and 0<size<=MAX_FILE,'ELF_STRING_TABLE_REQUIRED')
    table=loads[0][2]+address-loads[0][3]; data=raw[table:table+size]
    needed=[]
    for index in tags[1]:
        need(index<len(data),'ELF_NEEDED_BOUNDS')
        end=data.find(b'\0',index); need(end>=index and end-index<=255,'ELF_NEEDED_BOUNDS')
        try: name=data[index:end].decode('ascii')
        except UnicodeError: raise Refusal('ELF_NEEDED_NAME_REQUIRED') from None
        need(re.fullmatch(r'[A-Za-z0-9_+.-]+',name) and name not in ('.','..'),'ELF_NEEDED_NAME_REQUIRED')
        need(name not in needed,'ELF_NEEDED_DUPLICATE'); needed.append(name)
    return interpreter,needed


def read_regular(path):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_FILE,
             'RUNTIME_REGULAR_FILE_REQUIRED')
        chunks=[]; left=MAX_FILE+1
        while left:
            data=os.read(fd,min(left,1024*1024))
            if not data: break
            chunks.append(data); left-=len(data)
        raw=b''.join(chunks); after=os.fstat(fd)
        need(len(raw)<=MAX_FILE and
             (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'RUNTIME_READ_DRIFT')
        return raw,before
    finally: os.close(fd)


def capture(node, python, stdlib, libraries, *, python_target='/usr/bin/python3'):
    """Propose resolved, hashed inputs for a separate symlink-free root builder."""
    stdlib=Path(stdlib).resolve(strict=True)
    libraries=[Path(x).resolve(strict=True) for x in libraries]
    need(stdlib.is_dir() and all(x.is_dir() for x in libraries),'EXPLICIT_RUNTIME_DIRECTORIES_REQUIRED')
    need(python_target=='/usr/bin/python3','FIXED_PYTHON_TARGET_REQUIRED')
    entries={}; pending=[]

    def add(source,target,*,executable=False,allowed=None):
        source=Path(source).resolve(strict=True)
        need(allowed is None or any(source.is_relative_to(root) for root in allowed), 'RUNTIME_INPUT_ESCAPE')
        raw,info=read_regular(source)
        need(target.startswith('/') and str(Path(target))==target and '..' not in Path(target).parts,
             'RUNTIME_TARGET_REQUIRED')
        entry={'source':str(source),'target':target,'sha256':hashlib.sha256(raw).hexdigest(),
               'executable':bool(executable or info.st_mode & 0o111)}
        if target in entries:
            need(entries[target]==entry, 'RUNTIME_TARGET_COLLISION'); return
        entries[target]=entry
        if raw.startswith(b'\x7fELF'): pending.append((target,raw))
        elif target in ('/runtime/node',python_target): raise Refusal('SUPPORTED_ELF64_REQUIRED')

    add(node,'/runtime/node',executable=True)
    add(python,python_target,executable=True)
    for directory,dirs,names in os.walk(stdlib,followlinks=False):
        dirs[:]=sorted(x for x in dirs if x not in ('__pycache__','site-packages','dist-packages')
                       and not x.startswith('config-'))
        for name in dirs:
            need(not (Path(directory)/name).is_symlink(),'STDLIB_LINKED_DIRECTORY_FORBIDDEN')
        for name in sorted(names):
            # Never import host site customizations into the isolated interpreter.
            if name.endswith(('.pyc','.pyo')) or name in ('sitecustomize.py','usercustomize.py'): continue
            source=Path(directory)/name
            add(source,'/usr/lib/python3.13/'+source.relative_to(stdlib).as_posix(),allowed=[stdlib])
    visited=set()
    while pending:
        target,raw=pending.pop()
        if target in visited: continue
        visited.add(target)
        interpreter,needed=elf_requirements(raw)
        requests=[(name,'/lib/x86_64-linux-gnu/'+name) for name in needed]
        if interpreter: requests.append((Path(interpreter).name,interpreter))
        for name,destination in requests:
            choices=[]
            for directory in libraries:
                candidate=directory/name
                if candidate.exists():
                    resolved=candidate.resolve(strict=True)
                    need(any(resolved.is_relative_to(x) for x in libraries),'RUNTIME_LIBRARY_ESCAPE')
                    choices.append(resolved)
            need(choices and len(set(choices))==1,'EXPLICIT_LIBRARY_MISSING_OR_AMBIGUOUS')
            add(choices[0],destination,allowed=libraries)
    result={'version':1,'kind':'offline-runtime-inputs','physicalAccepted':False,
            'files':[entries[x] for x in sorted(entries)],
            'limitations':['Inputs are local byte candidates, not an independently accepted installed root.',
                           'No dlopen-by-name completeness or DNS/TLS/operational settings acceptance is inferred.',
                           'No target binary executed; no live resource, identity, ownership or mount changed.']}
    verify(result)
    return result


def verify(proposal):
    need(proposal.get('version')==1 and proposal.get('kind')=='offline-runtime-inputs' and
         proposal.get('physicalAccepted') is False and type(proposal.get('files')) is list,
         'OFFLINE_RUNTIME_PROPOSAL_REQUIRED')
    seen=set()
    for entry in proposal['files']:
        need(set(entry)=={'source','target','sha256','executable'} and type(entry['executable']) is bool,
             'EXACT_RUNTIME_INPUT_REQUIRED')
        target=entry['target']
        need(type(target) is str and target.startswith('/') and str(Path(target))==target and
             '..' not in Path(target).parts and target not in seen,'RUNTIME_TARGET_COLLISION')
        seen.add(target)
        raw,_=read_regular(entry['source'])
        need(hashlib.sha256(raw).hexdigest()==entry['sha256'],'RUNTIME_INPUT_DRIFT')
    return proposal


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node',required=True); parser.add_argument('--python',required=True)
    parser.add_argument('--stdlib',required=True)
    parser.add_argument('--library-directory',action='append',default=[])
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        result=capture(args.node,args.python,args.stdlib,args.library_directory)
        raw=json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n'
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out: out.write(raw); out.flush(); os.fsync(out.fileno())
        print(json.dumps({'physicalAccepted':False,'fileCount':len(result['files']),
                          'proposalSha256':hashlib.sha256(raw).hexdigest()}))
    except (OSError,ValueError,Refusal,struct.error):
        print('OFFLINE_RUNTIME_INPUTS_REFUSED'); raise SystemExit(75)


if __name__=='__main__': main()
