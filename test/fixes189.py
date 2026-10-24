#!/usr/bin/env python3
"""1.10.189: index builds that cannot deadlock each other at a start, the
domain's list of several kinds newest first without sorting the whole
window, and a clean start on Python 3.12.

    ./test/fixes189.py
"""
import random
import shutil
import sys
import tempfile
import threading
import time
import warnings
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
folder = tempfile.mkdtemp(prefix='isemon-189-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0})
store = isemon.Storage(isemon.DB_FILE)

print('\nThe lock index work is done under')
ok('never waited for inside one statement',
   ('SELECT pg_advisory_lock(' in source, source.count('advisory_wait(apart,')), (False, 3))


class Asked(object):
    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = 0

    def execute(self, sql):
        self.asked += 1
        said = self.answers.pop(0)

        class One(object):
            def fetchone(self):
                return {'ok': said}
        return One()


db = Asked([False, False, True])
ok('asked again until it is free', (isemon.advisory_wait(db, 1, every_s=0.01), db.asked),
   (True, 3))

print('\nThe domain’s events of several kinds, newest first')
random.seed(7)
now = time.time()
with store.db_write() as db:
    for i in range(1500):
        db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account) '
                   'VALUES (?,?,?,?,?,?)',
                   ('e%05d' % i, now - i * 7.0, 'dc1', 4624,
                    random.choice(['logon', 'kerberos', 'ntlm', 'explicit', 'lockout']),
                    'u%d' % (i % 30)))
every = [dict(r) for r in store.db.execute(
    "SELECT ident, ts, kind, account FROM win_events WHERE ts >= ? ORDER BY ts DESC",
    (now - 6000,))]
want = [r['ident'] for r in every if r['kind'] in ('logon', 'kerberos', 'ntlm', 'explicit')]
rows, total = store.win_rows(limit=100, since=now - 6000, kind='logon,kerberos,ntlm,explicit')
ok('the first page is the newest hundred of those kinds', [r['ident'] for r in rows], want[:100])
ok('...with how many there are', total, len(want))
rows, _total = store.win_rows(limit=100, offset=100, since=now - 6000,
                              kind='logon,kerberos,ntlm,explicit')
ok('...and the second page the next hundred', [r['ident'] for r in rows], want[100:200])
rows, _total = store.win_rows(limit=50, since=now - 6000, kind='logon,lockout', sort='ts',
                              desc=False)
ok('oldest first as well', [r['ident'] for r in rows],
   [r['ident'] for r in reversed(every) if r['kind'] in ('logon', 'lockout')][:50])
rows, _total = store.win_rows(limit=100, since=now - 6000, kind='logon,kerberos', account='u7')
ok('with the other filters still applied to every kind', [r['ident'] for r in rows],
   [r['ident'] for r in every if r['kind'] in ('logon', 'kerberos')
    and r['account'] == 'u7'][:100])
rows, _total = store.win_rows(limit=100, since=now - 6000, kind='lockout')
ok('one kind is asked as before', [r['ident'] for r in rows],
   [r['ident'] for r in every if r['kind'] == 'lockout'][:100])

print('\nPython 3.12')
with warnings.catch_warnings(record=True) as said:
    warnings.simplefilter('always')
    compile(source, 'isemon.py', 'exec')
ok('nothing to say when the program is compiled',
   [str(w.message) for w in said if issubclass(w.category, SyntaxWarning)], [])

if store.dialect.name == 'postgres':
    print('\nPostgreSQL: a build and a waiter at once')
    holder = store.split_conn()
    waiter = store.split_conn()
    trouble = []
    holder.execute('DROP TABLE IF EXISTS isemon_lock_probe')
    holder.execute('CREATE TABLE isemon_lock_probe (a INTEGER)')
    holder.execute('INSERT INTO isemon_lock_probe SELECT generate_series(1, 20000)')
    isemon.advisory_wait(holder, isemon.Storage.INDEX_LOCK_KEY)

    def wait_for_it():
        try:
            isemon.advisory_wait(waiter, isemon.Storage.INDEX_LOCK_KEY, every_s=0.2)
            waiter.execute('SELECT pg_advisory_unlock(%d)' % isemon.Storage.INDEX_LOCK_KEY)
        except Exception as e:
            trouble.append(str(e))
    other = threading.Thread(target=wait_for_it)
    other.start()
    time.sleep(0.5)
    try:
        holder.execute('CREATE INDEX CONCURRENTLY isemon_lock_probe_a ON isemon_lock_probe (a)')
    except Exception as e:
        trouble.append(str(e))
    holder.execute('SELECT pg_advisory_unlock(%d)' % isemon.Storage.INDEX_LOCK_KEY)
    other.join(30)
    ok('the build finishes while another waits its turn, with no deadlock', trouble, [])
    holder.execute('DROP TABLE IF EXISTS isemon_lock_probe')
    holder.close()
    waiter.close()

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
