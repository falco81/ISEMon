#!/usr/bin/env python3
"""1.10.179: every ban, letting back in and fold says who did it - a person
by name, or the program by itself and why.

    ./test/fixes179.py
"""
import os
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

folder = tempfile.mkdtemp(prefix='isemon-179-')
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
isemon.CONFIG.update({'api_port': 19972, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time()

print('\nWho did it, in the log')
said_lines = []
real_log = isemon.log
isemon.log = lambda text, level='info', *a, **k: said_lines.append(str(text))
try:
    daemon.ban('192.0.2.210', minutes=60, why='testing', by='falco')
    daemon.unban('192.0.2.210', by='falco')
    store.block('192.0.2.211', time.time() - 1, 'short', auto=True)
    store.sweep_expired()
    isemon.CONFIG.update({'fold_least': 4, 'fold_widest': 24, 'blacklist': 1})
    for k in range(1, 6):
        store.block('100.64.7.%d' % k, None, 'test')
    daemon.fold_apply(by='by itself')
finally:
    isemon.log = real_log
ok('a ban by hand says who', any('192.0.2.210 by hand by falco' in x for x in said_lines), True)
ok('...and so does letting it back in',
   any('let 192.0.2.210 back in by hand by falco' in x for x in said_lines), True)
ok('a ban that ran out says it was let go by itself',
   any('192.0.2.211' in x and 'back in automatically' in x for x in said_lines), True)
ok('a fold by itself says so, and which subnets',
   any('subnet(s) automatically' in x and '100.64.7.0/24' in x for x in said_lines), True)
ok('a ban by the counting says it was automatic',
   "log('blocked %s automatically - %s (%s)'" in source, True)
ok('...and a ban made longer', "log('%s held longer automatically" in source, True)
ok('who is said one way everywhere', (isemon.done_by(''), isemon.done_by('by itself'),
                                      isemon.done_by('falco')),
   ('automatically', 'automatically', 'by falco'))

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
