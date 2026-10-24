#!/usr/bin/env python3
"""1.10.185: searching - the firewall's lines narrowed by anything an hour at a
time, a verdict only where it can be, the refusals' and sign-ins' words an
index lookup on PostgreSQL.

    ./test/fixes185.py
"""
import ipaddress
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
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


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-185-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nA search for what the firewall blocked, over a day of sessions')
now = time.time()
with store.db_write() as db:
    for k, (verdict, brief) in enumerate([('block', 0), ('allow', 1), ('deny', 0),
                                          ('block', 0)]):
        db.execute("INSERT INTO fw_events (ident, ts, type, sub, verdict, area, brief, fw) "
                   "VALUES (?,?,?,?,?,?,?,?)",
                   ('t185-%d' % k, now - 60 * k, 'traffic', 'forward', verdict, 'session',
                    brief, 'fw1'))
rows, total = store.fw_rows(since=now - 86400, area='session', query='verdict:block')
ok('the blocked sessions are found', sorted(r['ident'] for r in rows), ['t185-0', 't185-3'])
rows, total = store.fw_rows(since=now - 86400, area='session', verdict='block')
ok('...by the drop-down as well', sorted(r['ident'] for r in rows), ['t185-0', 't185-3'])
rows, total = store.fw_rows(since=now - 86400, area='session', query='verdict:allow')
ok('...and the ones let through by theirs', [r['ident'] for r in rows], ['t185-1'])
ok('...asked only of the parts of each day that can hold them',
   "clause = '(verdict = ? AND brief = 0)' if v in FW_VERDICT_BRIEF0 else 'verdict = ?'"
   in source, True)
ok('no line without a page here, so the area is asked plainly',
   store.fw_unpaged_since(now - 86400), False)
with store.db_write() as db:
    db.execute("INSERT INTO fw_events (ident, ts, type, sub, verdict, brief, fw) "
               "VALUES ('t185-old', ?, 'traffic', 'forward', 'block', 0, 'fw1')", (now - 30,))
ok('...and one from before there were pages is still found', 't185-old' in [
    r['ident'] for r in store.fw_rows(since=now - 86400, area='session',
                                      query='verdict:block')[0]], True)
ok('an index for them, not the one taken away in 1.10.141',
   ('fw_kept_verdict_ts' in dict(isemon.Storage.LATER_INDEXES),
    'fw_kept_verdict_ts' in dict(isemon.Storage.OBSOLETE_INDEXES)), (True, False))
ok('a search narrowed by anything goes an hour at a time and stops when its time is up',
   "said=said if narrowed else None)" in source, True)

print('\nWords in the refusals\u2019 and sign-ins\u2019 boxes')
ok('an index on PostgreSQL, built behind the daemon whether or not a domain is read',
   ('def speed_up_auth(self, store):' in source,
    "threading.Thread(target=self.make_auth_searching_quick" in source), (True, True))
ok('...over every column those boxes look in',
   all(set(store.auth_word_columns(t, k)) <= set(isemon.PostgresDialect.AUTH_WORDS[t])
       for t in ('failed', 'passed')
       for k in ('vpn', 'dot1x-lan', 'otp', 'eduroam', 'tacacs', '')), True)
ok('...and nothing on the other engines', isemon.Dialect.speed_up_auth(store.dialect, store), '')

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
