"""Shared data for the DIRECT network unit's offline host models."""
import json
import re
import shlex
from pathlib import Path


def nft_source(source, network, token):
    js = Path(source).with_name('rebuildRelayDirect.js').read_text(encoding='utf-8')
    template = js.split('const nft = `', 1)[1].split('`;', 1)[0]
    values = {'backupId': token, **{f'd.{key}': value for key, value in network.items()}}
    return re.sub(r'\$\{([^}]+)\}', lambda m: str(values[m[1]]), template).encode()


def nft_rows(network, token):
    rows = json.loads(Path(__file__).with_name('rebuildRelayNetworkNft.fixture.json').read_bytes())['nftables']
    address, length = network['clientCidr'].split('/')
    rows[1]['table']['comment'] = token
    for row in rows[2:]:
        for expr in row.get('rule', {}).get('expr', []):
            if 'tproxy' in expr:
                expr['tproxy']['port'] = network['tproxyPort']
            elif 'mangle' in expr:
                expr['mangle']['value'] = network['fwmark']
            elif 'match' in expr:
                match = expr['match']
                left = match['left']
                if left == {'payload': {'protocol': 'ip', 'field': 'saddr'}}:
                    match['right'] = {'prefix': {'addr': address, 'len': int(length)}}
                elif left == {'meta': {'key': 'mark'}}:
                    match['right'] = network['fwmark']
                elif left == {'payload': {'protocol': 'th', 'field': 'dport'}}:
                    match['right'] = network['tproxyPort']
    return rows


def systemctl_start(unit, present='native'):
    def show(line):
        argv = shlex.split(line)
        value = ' '.join(argv) if present == 'native' else shlex.join(argv)
        return (f'{{ path={argv[0]} ; argv[]={value} ; ignore_errors=no ; '
                'start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }')
    return ' '.join(show(line.removeprefix('ExecStart=')) for line in unit.decode().splitlines()
                    if line.startswith('ExecStart='))
