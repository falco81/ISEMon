#!/usr/bin/env python3
"""1.10.282: What the firewall is carrying, read quickly, and waited for.

- The ban history beside every address on the router is read for all of them
  at once, a few hundred addresses a statement by the index on the address -
  not one search of the whole history (a LIKE over three columns, counted
  and then read) per address, which on a router carrying thousands and a
  big history was most of the minutes the page took. The same story, the
  newest eight, for each.
- The page waits for the read as long as nginx waits for it (900 s) rather
  than giving up after 60 s.
- Settings -> The firewall: Waiting for the router's lists (s), five minutes
  unless it is said otherwise (30 to 1800), for this read and every sync.

    ./test/fixes282_router_read.py
"""
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
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


work = Path(tempfile.mkdtemp(prefix='isemon-282-'))
try:
    state = work / 'state'
    state.mkdir()
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'b'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'token'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 1, 'mikrotik_host': '192.0.2.9',
                          'mikrotik_sync': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)

    print('The setting')
    ok('five minutes unless said otherwise', (isemon.DEFAULTS['mikrotik_read_s'],
                                             daemon.mikrotik_read_s()), (300, 300))
    isemon.CONFIG['mikrotik_read_s'] = 900
    ok('raised: the read waits for it', daemon.mikrotik_read_s(), 900)
    sent = []
    real_run = daemon.mikrotik_run
    daemon.mikrotik_run = lambda command, fw='mikrotik', timeout=None: (
        sent.append(timeout) or '0   address=192.0.2.1 comment="isemon x"\n')
    daemon.mikrotik_list_print('/ip', 'ISEMonDROP', 'mikrotik')
    ok('...and the router is asked with it', sent[-1], 900)
    daemon.mikrotik_run = real_run
    ok('30 to 1800 s', isemon.check_setting('mikrotik_read_s', 1800), 1800)
    try:
        isemon.check_setting('mikrotik_read_s', 5)
        ok('...5 s refused', False)
    except ValueError:
        ok('...5 s refused', True)
    isemon.CONFIG['mikrotik_read_s'] = 300

    print('\nThe ban history of every address, at once')
    N = 1200
    entries = []
    with store.db_write() as db:
        for i in range(N):
            ip = '10.%d.%d.%d' % (i // 65536, (i // 256) % 256, i % 256)
            entries.append({'address': ip, 'comment': 'isemon x', 'ours': True, 'timeout': None})
            for k in range(3 if i % 7 else 11):
                db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) '
                           'VALUES (?, ?, ?, ?, ?, ?)',
                           (1700000000 + i * 100 + k, ip, 'blocked', 'reason %d-%d' % (i, k), 1, 'x'))
        # a range on the list, its history under the range; and one written /32
        db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?, ?, ?, ?, ?, ?)',
                   (1800000000, '198.51.100.0/24', 'blocked', 'the range', 1, 'x'))
        db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?, ?, ?, ?, ?, ?)',
                   (1800000001, '203.0.113.5/32', 'blocked', 'as /32', 1, 'x'))
        # what a LIKE would have found too: another address that contains it
        db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?, ?, ?, ?, ?, ?)',
                   (1800000002, '110.0.0.1', 'blocked', 'not this one', 1, 'x'))
    entries += [{'address': '198.51.100.0/24', 'comment': 'isemon x', 'ours': True, 'timeout': None},
                {'address': '203.0.113.5', 'comment': 'isemon x', 'ours': True, 'timeout': None}]
    daemon.mikrotik_entries = lambda remember=True, fw='mikrotik', **k: list(entries)
    searched = []
    real = store.block_events

    def counted(*a, **k):
        searched.append(1)
        return real(*a, **k)
    store.block_events = counted
    began = time.time()
    pic = daemon.router_picture()
    took = time.time() - began
    store.block_events = real
    rows = {r['address']: r for r in pic['carrying']}
    ok('every entry there', len([r for r in pic['carrying'] if r.get('ours')]) >= N + 2)
    ok('no search of the whole history per address (only the few not carried)',
       len(searched) <= daemon.NOT_CARRIED_STORIES)
    print('          (%d entries with their stories in %.2f s)' % (N + 2, took))
    want = [h for h in real(60, text='10.0.0.7')[0] if str(h['ip']).split('/')[0] == '10.0.0.7'][:8]
    ok('the same story as before: the newest eight of its own, newest first',
       [x['why'] for x in rows['10.0.0.7']['story']], [h['why'] for h in want])
    ok('...eight at most', len(rows['10.0.0.7']['story']), 8)
    ok('...three where there are three', [x['why'] for x in rows['10.0.0.1']['story']],
       ['reason 1-2', 'reason 1-1', 'reason 1-0'])
    ok('a range on the list: its own history', [x['why'] for x in rows['198.51.100.0/24']['story']],
       ['the range'])
    ok('an address written as /32 in the history: found', [x['why'] for x in
                                                          rows['203.0.113.5']['story']], ['as /32'])
    ok('another address that only contains it: not its story',
       'not this one' not in [x['why'] for x in rows['10.0.0.1']['story']])
    ok('block_events_for: grouped, per address, newest first, in chunks',
       {k: [r['why'] for r in v] for k, v in store.block_events_for(
           ['10.0.0.1', '10.0.0.2', '10.0.0.3', 'nothing'], per=2, chunk=2).items()},
       {'10.0.0.1': ['reason 1-2', 'reason 1-1'], '10.0.0.2': ['reason 2-2', 'reason 2-1'],
        '10.0.0.3': ['reason 3-2', 'reason 3-1']})

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the read waited for as long as nginx waits (900 s), every other read as before',
       "isemon_relay($reads[$what] . $tail, 'GET', null, $what === 'router' ? 900.0 : 60.0);" in page)
    ok('the setting on The firewall, for a MikroTik', ("'mikrotik_chunk', 'mikrotik_read_s'],"
                                                     in page, "|| key === 'mikrotik_read_s')" in page),
       (True, True))
    nginx = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
    ok('...nginx waits 900 s for index.php', 'fastcgi_read_timeout 900s;' in nginx)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
