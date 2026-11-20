'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { existsSync, readlinkSync } = require('node:fs');
const { join } = require('node:path');

const probe = String.raw`
import os, runpy, subprocess, sys

# Only fixture setup issues netlink mutations, in a disposable netns.
assert os.readlink('/proc/self/ns/net') != sys.argv[2]
project = runpy.run_path(sys.argv[1])['network_projection']
h = project.__globals__
d = h['routing'](dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=1, routeTable=177))
priority = str(h['PRIORITY'])
token = 'a' * 32
ip_read = h['ip']


def mutate(*args):
    subprocess.run(['/usr/sbin/ip', '-4', *args], check=True, timeout=4)


def snapshot():
    return ip_read('rule', 'show'), ip_read('route', 'show', 'table', 'all')


def observe(**kw):
    return project(d, token, **kw)


def refuses(**kw):
    before = snapshot()
    try:
        observe(**kw)
    except h['Refusal'] as error:
        assert str(error) == 'NETWORK_CONFLICT', str(error)
    else:
        raise AssertionError('RPDB conflict admitted')
    assert snapshot() == before


empty = dict(rule=False, route=False, nft=None)
assert observe() == empty
rule = ('priority', priority, 'from', d['clientCidr'], 'fwmark', str(d['fwmark']), 'table', str(d['routeTable']))
route = ('local', '0.0.0.0/0', 'dev', 'lo', 'table', str(d['routeTable']))
mode = sys.argv[3]
if mode == 'split source lifecycle':
    mutate('route', 'add', *route)
    mutate('rule', 'add', *rule)
    own, = [row for row in snapshot()[0] if row['priority'] == int(priority)]
    # iproute2 v6.15 ip/iprule.c:print_rule() emits these as separate JSON fields.
    assert (own['src'], own['srclen']) == ('10.255.1.0', 24), own
    for removing in (False, True):
        assert observe(removing=removing) == dict(empty, rule=True, route=True)
    mutate('rule', 'del', *rule)
    assert observe(removing=True) == dict(empty, route=True)
    mutate('route', 'del', *route)
    assert observe(removing=True) == empty
elif mode == 'legacy and invalid encodings':
    mutate('rule', 'add', *rule)
    rules, _ = snapshot()
    own, = [row for row in rules if row['priority'] == int(priority)]
    others = [row for row in rules if row is not own]
    # Inject only encodings this iproute2 cannot produce (or historical combined
    # CIDR); still use the real route dump, nft readback and projector.
    def supply(rows):
        h['ip'] = lambda *args: rows if args == ('rule', 'show') else ip_read(*args)

    legacy = dict(own, src=d['clientCidr'])
    legacy.pop('srclen')
    supply([*others, legacy])
    for removing in (False, True):
        assert observe(removing=removing) == dict(empty, rule=True)
    for bad in [dict(legacy, srclen=24), dict(legacy, srclen=None), dict(legacy, src=own['src']), own | {'srclen': '24'},
                own | {'srclen': 24.0}, own | {'srclen': True}, own | {'srclen': 25},
                own | {'src': 'all'}, own | {'src': '10.255.1.1'}, own | {'fwmark': True},
                legacy | {'fwmark': 1.0}, own | {'priority': float(priority)},
                own | {'fwmask': '0xf'}, own | {'action': 'blackhole'}, own | {'not': None}]:
        supply([*others, bad])
        for removing in (False, True):
            refuses(removing=removing)
    for bad in [dict(others[0], priority=False), dict(others[0], srclen=0)]:
        supply([bad, *others[1:]])
        refuses()
elif mode == 'foreign 220 and competing rules':
    # An exact lookalike is not provenance. Do not skip it, or its use of
    # a caller-selected table, even though the IPv4 table contains no routes.
    mutate('rule', 'add', 'priority', '220', 'table', '220')
    assert any(row == dict(priority=220, src='all', table='220') for row in snapshot()[0])
    assert not any(row.get('table') == '220' for row in snapshot()[1])
    refuses()
    assert observe(removing=True) == empty  # Existing removal contract: unrelated rule is untouched.
    d['routeTable'] = 220
    for removing in (False, True):
        refuses(removing=removing)
    d['routeTable'] = 177
    mutate('rule', 'add', *rule)
    mutate('rule', 'add', 'priority', '221', 'from', d['clientCidr'], 'table', '177')
    for removing in (False, True):
        refuses(removing=removing)
else:
    raise AssertionError(mode)
`;

const unshare = '/usr/bin/unshare';
const opts = ['--user', '--map-root-user', '--net', '--'];
for (const mode of ['split source lifecycle', 'legacy and invalid encodings', 'foreign 220 and competing rules']) {
    test(`DIRECT IPv4 RPDB: ${mode}`, t => {
        if (process.platform !== 'linux' || ![unshare, '/usr/sbin/ip', '/usr/sbin/nft',
            '/usr/bin/python3', '/sys/module/nf_tables'].every(existsSync)) {
            t.skip('requires Linux with nftables already loaded and local namespace tools');
            return;
        }
        const available = spawnSync(unshare, [...opts, '/usr/bin/true'], { encoding: 'utf8', timeout: 3000 });
        if (available.status !== 0 && /Operation not permitted|Permission denied/.test(available.stderr ?? '')) {
            t.skip('unprivileged user/network namespaces unavailable');
            return;
        }
        assert.equal(available.status, 0, available.stderr || available.error?.message);
        const result = spawnSync(unshare, [...opts, '/usr/bin/python3', '-I', '-B', '-c', probe,
            join(__dirname, '..', 'rebuildRelayDirectHost.py'), readlinkSync('/proc/self/ns/net'), mode],
        { encoding: 'utf8', timeout: 12000 });
        assert.equal(result.status, 0, result.stderr || result.error?.message);
    });
}
