#!/usr/bin/env python3
"""The banning, where 1.10.155 found it wrong.

Each of these was found by reading the code and then made to happen:

- a burst read from a backlog earned only the first rung, never "for good":
  what came after the ban was weighed against this machine's clock rather
  than the records' own time, and in fives;
- a whitelist changed anywhere but the page left the bans it now covers in
  place, and they could even be lengthened;
- a ladder of "forever" alone gave sixty-minute bans;
- folding made four ten-minute bans into a whole street for good;
- whitelisting one innocent address in a folded street freed every attacker
  folded into it;
- erasing the ban history banned addresses again for attempts they had
  already served a ban for;
- a ban lengthened while the expiry sweep was looking was deleted as having
  run out.

    ./test/banning.py
"""
import sys
import tempfile
import time
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


def fresh(**cfg):
    folder = tempfile.mkdtemp(prefix='isemon-ban-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'b.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'watch_devices': '', 'feeds_ban': 0, 'judge_max_age_h': 0,
                          'geo': 0, 'mikrotik1': 0, 'mikrotik2': 0})
    isemon.CONFIG.update(cfg)
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    daemon.feed_wanted = lambda: []
    return store, daemon


def fail(store, ip, at, user='u', key=None):
    return store.add_failed({'session': key or 's/%s/%s/%s' % (ip, at, user), 'ts': at,
                             'ip': ip, 'username': user, 'device': 'FTD-VPN',
                             'server': 'ise2', 'detail': '{}'})


print('\nA burst read from a backlog')
store, daemon = fresh(block_tries=5, block_window_min=10, block_lots=25, block_bogus_tries=0)
now = time.time()
ip = '203.0.113.9'
for i in range(60):
    ts = now - 300 + i * 5
    fail(store, ip, ts, key='b%d' % i)
    daemon.judge_refusal(ip, isemon._AtTime(ts), ['FTD-VPN'])
row = store.blocked_one(ip)
ok('sixty attempts in five minutes, read and judged one by one: out for good',
   row and row['until'], None)

print('\nThe whitelist, changed outside the page')
store, daemon = fresh(block_tries=3, block_window_min=10)
now = time.time()
ip = '198.51.100.7'
for i in range(3):
    fail(store, ip, now - 30 + i)
daemon.maybe_block(ip, isemon._AtTime(now))
daemon.settings_changed_underneath()
isemon.CONFIG['never_block'] = '198.51.100.0/24'
daemon.settings_changed_underneath()
ok('a range put in never_block by the file or a HUP lets the ban in it go',
   store.blocked_one(ip), None)
store, daemon = fresh(block_tries=3, block_window_min=10)
for i in range(3):
    fail(store, ip, now - 30 + i)
daemon.maybe_block(ip, isemon._AtTime(now))
until = store.blocked_one(ip)['until']
isemon.CONFIG['never_block'] = '198.51.100.0/24'
daemon._spare_from = None
for i in range(3):
    fail(store, ip, time.time() + 5 + i, key='x%d' % i)
daemon.maybe_escalate(ip, isemon._AtTime(time.time() + 8))
ok('...and an address that is spared is never held longer meanwhile',
   store.blocked_one(ip)['until'], until)

print('\nThe ladder')
ok('"forever" alone is accepted', isemon.check_setting('block_ladder', 'forever'), 'forever')
try:
    isemon.check_setting('block_ladder', '10, forever, 60')
    ok('a step after "forever" is refused rather than dropped', 'accepted', 'refused')
except ValueError:
    ok('a step after "forever" is refused rather than dropped', True)
store, daemon = fresh(block_tries=3, block_window_min=10, block_ladder='forever')
ok('...and it bans for good, every time', daemon.block_length('192.0.2.1')[1], 'for good')
for i in range(3):
    fail(store, '192.0.2.1', now - 30 + i)
daemon.maybe_block('192.0.2.1', isemon._AtTime(now))
ok('...on the list as for good', store.blocked_one('192.0.2.1')['until'], None)

print('\nFolding')
store, daemon = fresh(block_tries=3, block_window_min=10, block_bogus_tries=0)
for k in range(4):
    one = '198.51.100.%d' % (10 + k)
    for i in range(3):
        fail(store, one, now - 30 + i, key='%s%d' % (one, i))
    daemon.maybe_block(one, isemon._AtTime(now))
daemon.fold_apply(by='test')
ok('four short bans are not folded into a street banned for good',
   sorted(r['ip'] for r in store.blocked_all()),
   ['198.51.100.10', '198.51.100.11', '198.51.100.12', '198.51.100.13'])
ok('...so an address in that street that did nothing is not banned',
   store.blocked_until('198.51.100.200'), None)
store, daemon = fresh(block_tries=3, block_window_min=10, block_bogus_tries=0)
for k in range(5):
    daemon.ban('198.51.100.%d' % (10 + k), why='attacker')
daemon.fold_apply(by='test')
ok('five bans for good are folded', [r['ip'] for r in store.blocked_all()],
   ['198.51.100.0/24'])
daemon.whitelist_add('198.51.100.200', note='partner')
ok('whitelisting an innocent address in it puts the attackers back, one by one',
   sorted(r['ip'] for r in store.blocked_all()),
   ['198.51.100.10', '198.51.100.11', '198.51.100.12', '198.51.100.13', '198.51.100.14'])

print('\nErasing the history of bans')
store, daemon = fresh(block_tries=3, block_window_min=60, block_bogus_tries=0)
ip = '198.51.100.50'
for i in range(3):
    fail(store, ip, now - 120 + i, key='%d' % i)
daemon.maybe_block(ip, isemon._AtTime(now - 117))
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 1, ip))
store.sweep_expired()
store.forget_blocked_history()
ok('an address whose ban ran out is not banned again for the same attempts',
   (daemon.judge_anything_missed(), store.blocked_until(ip)), (0, None))

print('\nThe expiry sweep and a ban lengthened meanwhile')
store, daemon = fresh(block_tries=3, block_window_min=10, block_bogus_tries=0)
ip = '198.51.100.60'
for i in range(3):
    fail(store, ip, now - 30 + i, key='%d' % i)
daemon.maybe_block(ip, isemon._AtTime(now - 27))
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 1, ip))
real = store.db_write
first = {'done': False}


class Between(object):
    def __enter__(self):
        if not first['done']:
            first['done'] = True
            for i in range(3):
                fail(store, ip, time.time() + 1 + i, key='e%d' % i)
            daemon.maybe_escalate(ip, isemon._AtTime(time.time() + 4))
        self.cm = real()
        return self.cm.__enter__()

    def __exit__(self, *a):
        return self.cm.__exit__(*a)


store.db_write = lambda: Between() if not first['done'] else real()
swept = store.sweep_expired()
store.db_write = real
ok('the lengthened ban stays, and is not logged as having run out',
   (swept, bool(store.blocked_until(ip))), (0, True))

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
