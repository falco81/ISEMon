#!/usr/bin/env python3
"""1.10.368: speed on a very large database, round two - the writing and the
upkeep (how long the write lock is held), the Domain and Traffic questions
still slow on PostgreSQL, and the lists of the pages.

    ./test/fixes368_speed.py
"""
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
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


folder = Path(tempfile.mkdtemp(prefix='isemon-368-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'winsec': 1})
store = isemon.Storage(isemon.DB_FILE)
db = store.db
src = (ROOT / 'isemon.py').read_text()
page = (ROOT / 'web' / 'index.php').read_text()

print('The indexes')
names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
ok('the account and group changes\' cards have theirs', 'win_change_ts' in names)
ok('(mark, ts), which nothing could use, is gone', 'win_mark_ts' in names, False)

print('Counting the domain events ahead of time, an hour at a time')
ok('an hour a transaction', store.ROLL_BUILD_STRIDE, isemon.ROLL_HOUR)
NOW = int(time.time() // 3600) * 3600
events = []
for n in range(300):
    events.append({'ident': 'e%d' % n, 'ts': NOW - 3 * 86400 + n * 700, 'server': 'DC%d' % (n % 2),
                   'event': [4624, 4625, 4769][n % 3],
                   'kind': ['logon', 'logon-failed', 'kerberos'][n % 3],
                   'account': 'user%d' % (n % 7), 'machine': 'PC%d' % (n % 5),
                   'ip': '10.0.0.%d' % (n % 9), 'said': 'x' if n % 3 == 1 else ''})
try:
    store.note_win_events(events)
except Exception as e:                                # noqa: BLE001
    print('  (could not write the made-up events: %s)' % e)
total = store.roll_build_now('test')
ok('every event counted', total, store.rows_in('win_events'))
hourly = {tuple(r) for r in db.execute(
    'SELECT span, at, dim, val, kind, mach, quiet, told, n FROM win_rollup ORDER BY 1,2,3,4,5')}
store.ROLL_BUILD_STRIDE = isemon.ROLL_DAY
store.roll_build_now('test')
daily = {tuple(r) for r in db.execute(
    'SELECT span, at, dim, val, kind, mach, quiet, told, n FROM win_rollup ORDER BY 1,2,3,4,5')}
store.ROLL_BUILD_STRIDE = isemon.ROLL_HOUR
ok('...the very buckets a day at a time made', hourly == daily and len(hourly) > 0)
ok('buckets of a day are still counted a day at a time',
   'stride = max(int(self.ROLL_BUILD_STRIDE), int(span))' in src)

print('The upkeep')
ok('an index built behind the daemon takes the file\'s write lock as every writer does',
   'with self._write:\n                        apart.execute(text)' in src)
ok('the tidying rests as long as a stride held the lock',
   'time.sleep(max(0.01, min(1.0, time.time() - stride_at)))' in src)
ok('the statistics are gathered (ANALYZE, a thousand rows an index)',
   "self.store.db.raw.execute('ANALYZE')" in src)
for col, kind in (('device', 'vpn'), ('server', 'vpn'), ('device', 'tacacs')):
    db.execute('INSERT INTO seen_values (tbl, col, kind, val, fold, n, first, last) '
               "VALUES ('failed', ?, ?, 'old-one', 'old-one', 1, 1, 1)", (col, kind))
db.commit()
store.add_failed({'session': 's1', 'ts': time.time(), 'ip': '198.51.100.7', 'username': 'u',
                  'kind': 'vpn', 'device': 'asa-1'})
store.seen_flush()
gone = store.seen_prune()
left = {(r['col'], r['kind']) for r in db.execute(
    "SELECT col, kind FROM seen_values WHERE tbl = 'failed' AND val = 'old-one'")}
ok('values no row holds any more let go, a column at a time', (gone >= 3, left), (True, set()))
ok('...down the key, never a walk of the table\'s part',
   'SEARCH seen_values USING' in ' '.join(str(r[3]) for r in db.execute(
       'EXPLAIN QUERY PLAN DELETE FROM seen_values WHERE tbl = ? AND col = ? AND kind = ? '
       'AND last < ?', ('failed', 'device', 'vpn', 1.0))))

print('The questions')
ok('the RADIUS refusals beside a domain\'s, forty stretches a statement',
   "' OR '.join(['(ts >= ? AND ts <= ?)'] * len(some))" in src)
ok('sorted by sent or received alone: the big sessions first, where that is exact',
   "if order in ('(sent + rcvd)', 'sent', 'rcvd') and desc and self.fw_big_index():" in src)
ok('a text search counts in longer strides while it is quick',
   'step = min(step * 2, 86400)' in src)
ok('the event numbers of the same count in one order',
   "sorted(shape['events'].items(), key=lambda one: (-one[1], one[0]))" in src)

print('The lists of the pages')
ok('the refresh of a slow list never draws its old bans again',
   'delete old.banned;' in page and 'delete old.now;' in page)
ok('after Stop a list is held off about a minute, not twenty', 'lane.took = 3000;' in page)
ok('a filter\'s choice stays shown though the list does not hold it',
   'if (was && values.indexOf(was) < 0) values.push(was);' in page)
ok('a count at the cap is said to be more than it',
   "['Refused in this window', (d.capped ? 'more than ' : '') + num(d.total)]" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
