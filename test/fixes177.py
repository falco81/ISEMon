#!/usr/bin/env python3
"""1.10.177: what a very busy site showed - the VPN put together from what
arrived since the last look, the public lists held in memory, the counts on
the Banned page kept for each address, the sync of the router without the
Banned page, and work slow on purpose not said as a warning.

    ./test/fixes177.py
"""
import gzip
import json
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

folder = tempfile.mkdtemp(prefix='isemon-177-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': 19970, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time()
logs = Path(folder) / 'logs'
logs.mkdir()


import random

def vpn_lines(n, people, seed):
    r = random.Random(seed)
    out = []
    ts = NOW - 6 * 86400
    for k in range(n):
        ts += r.random() * 30
        who = 'user%02d' % r.randrange(people)
        ip = '198.51.100.%d' % r.randrange(1, 40)
        inner = '10.8.0.%d' % r.randrange(1, 30)
        fw = r.choice(['ftd-a', 'ftd-a', 'ftd-b'])
        roll = r.random()
        if roll < 0.2:
            msgid, f = r.choice(['113039', '722022', '716001']), {}
        elif roll < 0.35:
            msgid, f = r.choice(['113019', '716002']), {'reason': 'User Requested'}
        elif roll < 0.5:
            msgid, f = '737016', {'assigned': inner}
            if r.random() < 0.5:
                who = ''
        elif roll < 0.6:
            msgid, f = r.choice(['109210', '737031']), {'assigned': inner}
            who = ''
        elif roll < 0.75:
            msgid, f = '722051', {'assigned': inner, 'group_policy': 'GP%d' % r.randrange(3)}
            if r.random() < 0.3:
                f['handle'] = 'h%d' % r.randrange(20)
        elif roll < 0.85:
            msgid, f = '737006', {'handle': 'h%d' % r.randrange(20), 'pool': 'P1',
                                  'assigned': inner}
            who = ''
        elif roll < 0.92:
            msgid, f = r.choice(['722037', '722035']), {'reason': 'DPD', 'packet': '1500',
                                                        'threshold': '1400'}
        else:
            msgid, f = '', {'tunnelid': str(r.randrange(1, 9)), 'assigned': inner}
        f['msgid'] = msgid
        out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 'client-vpn', 'type': 'event',
                    'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-stats', 'tunnel-down',
                                                      '']) if not msgid else '',
                    'verdict': r.choice(['', '', '', 'fail']) if r.random() < 0.1 else '',
                    'srcip': ip, 'dstip': '', 'user': who, 'msg': '', 'sent': r.randrange(9999),
                    'rcvd': r.randrange(9999), 'duration': r.randrange(0, 900),
                    'fields': f})
        if r.random() < 0.05:
            out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 's2s-vpn', 'type': 'event',
                        'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-down',
                                                          'tunnel-stats', 'install_sa']),
                        'verdict': '', 'srcip': '203.0.113.%d' % r.randrange(1, 6),
                        'dstip': '192.0.2.1', 'user': '', 'msg': '', 'sent': 1, 'rcvd': 1,
                        'duration': 60, 'fields': {'spi': str(r.randrange(99))}})
    return out


print('\nThe VPN as it stands, made from what arrived since the last look')
rows = vpn_lines(8000, 60, 177)
whole = isemon.fw_vpn_fold(json.loads(json.dumps(rows)), NOW)
feed, result = isemon.fw_vpn_folder()
said = []
for at in range(0, len(rows), 997):
    feed(json.loads(json.dumps(rows[at:at + 997])))
    said.append(result(NOW))              # looked at between, as the page does
ok('fed a piece at a time, looked at between: the same clients and tunnels',
   json.dumps(said[-1], sort_keys=True), json.dumps(whole, sort_keys=True))
ok('...and what was handed out before is not changed by what came after',
   json.dumps(said[0], sort_keys=True) == json.dumps(
       isemon.fw_vpn_fold(json.loads(json.dumps(rows[:997])), NOW), sort_keys=True))

print('\nThe same, through the daemon: a week once, then what is new')
fed = []
real_rows = store.fw_vpn_rows
WALL = [rows[len(rows) // 2]['ts']]


def fake_rows(since, fw='', strict=False):
    fed.append(since)
    got = [dict(r, ident='v%d' % k, fields=dict(r['fields']))
           for k, r in enumerate(rows) if since <= r['ts'] <= WALL[0]]
    return sorted(got, key=lambda r: r['ts'])


real_batches = store.fw_vpn_batches
store.fw_vpn_batches = lambda since, fw='', strict=False, size=0: iter([fake_rows(since, fw, strict)])
daemon._fw_vpn_now('')
WALL[0] = rows[-1]['ts']
second = daemon._fw_vpn_now('')
store.fw_vpn_batches = real_batches
# ...of the firewall furthest behind: here two, a line every fifteen
# seconds between them.
ok('the second look reads only from shortly before the newest line it had',
   fed[1] >= rows[len(rows) // 2]['ts'] - daemon.FW_VPN_BEHIND_S - 600)
ok('...of each firewall', sorted(daemon._vpn_folds['']['hi']), ['ftd-a', 'ftd-b'])


def strip(d):
    # Without what the daemon puts beside each: the country, private or not.
    plain = {k: d[k] for k in ('ended_clients', 'down_tunnels')}
    for k in ('clients', 'tunnels'):
        plain[k] = [{a: b for a, b in one.items() if a not in ('cc', 'private')}
                    for one in d[k]]
    return json.dumps(plain, sort_keys=True, default=str)


whole_read = isemon.fw_vpn_fold(sorted([dict(r, ident='v%d' % k, fields=dict(r['fields']))
                                       for k, r in enumerate(rows) if r['ts'] >= fed[0]],
                                      key=lambda r: r['ts']), second['made'])
ok('...and comes to what reading all of it at once does', strip(second), strip(whole_read))
daemon.forget_all_kept('a test')
ok('an erase makes it whole again', '_vpn_folds' in daemon.__dict__, False)

print('\nThe public lists, held in memory')


def pa(a):
    return isemon.pack_address(a)[0]


store.put_feed('listA', [(pa('198.51.100.0'), pa('198.51.100.255'), 4),
                         (pa('203.0.113.8'), pa('203.0.113.8'), 4)])
store.put_feed('listB', [(pa('198.51.100.128'), pa('198.51.100.200'), 4)])
asked = ['198.51.100.7', '198.51.100.150', '203.0.113.8', '203.0.113.9', '2001:db8::1']
from_memory = [sorted(store.feeds_with(ip)) for ip in asked]
store.FEED_INDEX_MOST = 0                  # too many to hold: asked of the database
store._feed_index = None
from_db = [sorted(store.feeds_with(ip)) for ip in asked]
store.FEED_INDEX_MOST = isemon.Storage.FEED_INDEX_MOST
store._feed_index = None
ok('the same lists for each address, from memory and from the database', from_memory, from_db)
ok('...and the right ones', from_memory, [['listA'], ['listA', 'listB'], ['listA'], [], []])
store.drop_feed('listB')
ok('a list dropped is dropped from memory too', sorted(store.feeds_with('198.51.100.150')),
   ['listA'])

print('\nThe Banned page and the router')
ok('the sync of the router no longer works out the whole Banned page',
   "want = {same_address(r['ip']): r for r in self._blocked_for_router()}" in source)
for k in range(3):
    store.add_failed({'session': 'pb%d' % k, 'ts': NOW - 60 + k, 'ip': '192.0.2.90',
                      'username': 'n%d' % (k % 2), 'kind': 'vpn', 'server': 'ise1'})
store.block('192.0.2.90', None, 'test', auto=False)
asked_n = []
real_names = store.names_for


def counting_names(ips, *a, **k):
    asked_n.append(list(ips))
    return real_names(ips, *a, **k)


store.names_for = counting_names
one = [r for r in daemon._blocked_list_now() if r['ip'] == '192.0.2.90'][0]
daemon._blocked_list_now()
store.names_for = real_names
ok('the names tried from a banned address are counted once, then kept',
   (sorted(n['name'] for n in one['names']), len([a for a in asked_n if a])),
   (['n0', 'n1'], 1))
router = [r for r in daemon._blocked_for_router() if r['ip'] == '192.0.2.90'][0]
ok('...the router is told what it needs', (router['forever'], bool(router['spared'])),
   (True, False))

print('\nSlow on purpose is not a warning')
ok('the check of the whole database, and an index built behind the daemon',
   "Db.patiently('checking the database', quiet=True)" in source
   and "patient = Db.patiently('building the index %s' % name, quiet=True)" in source)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
