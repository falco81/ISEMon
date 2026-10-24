#!/usr/bin/env python3
"""1.10.180: when everything is slow and the database is not - the moments
the whole program stands still, and transactions held open with nothing
asked of them, written down with what every thread was doing.

    ./test/fixes180.py
"""
import re
import shutil
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


folder = tempfile.mkdtemp(prefix='isemon-180-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'isemon.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nA transaction is noted while it is open')
if store.dialect.name != 'sqlite':
    with store.db_write() as db:
        db.execute('SELECT 1 AS one')
        mine = [one for one in isemon.Db.OPEN.values() if one[0] == threading.get_ident()]
        ok('...with its thread and its last question', (len(mine), 'SELECT 1' in mine[0][3]),
           (1, True))
    ok('...and forgotten when it ends',
       [one for one in isemon.Db.OPEN.values() if one[0] == threading.get_ident()], [])
else:
    ok('(the file engine opens none of its own)', True)

print('\nThe whole program standing still')
said = []
real = isemon.log
isemon.log = lambda text, level='info', *a, **k: said.append(str(text))
daemon.STALL_S = 2.0
daemon.STALL_IDLE_TX_S = 2.0
watch = threading.Thread(target=daemon.watch_for_stalls, daemon=True)
watch.start()
time.sleep(1.5)
began = time.time()
re.match(r'(a+)+$', 'a' * 27 + 'b')       # holds the interpreter, never lets go
held = time.time() - began
time.sleep(1.5)
ok('the stall was long enough to be seen', held >= 2.5, True)
ok('it is said in the log', any('stood still' in x for x in said), True)
dump = daemon.stall_file().read_text()
ok('...and what held it up is in the file beside the log', 'in match' in dump, True)

print('\nA transaction held open with nothing asked of it')
isemon.Db.OPEN[-1] = [threading.get_ident(), time.time() - 9, time.time() - 8, 'UPDATE ptr', False]
time.sleep(2.5)
isemon.Db.OPEN.pop(-1, None)
ok('it is said, with the thread that holds it and its last question',
   any('has held a transaction open' in x and 'UPDATE ptr' in x for x in said), True)
daemon.stopping.set()
watch.join(5)
isemon.log = real
ok('the watch stops with the daemon', watch.is_alive(), False)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
