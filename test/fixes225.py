#!/usr/bin/env python3
"""1.10.225: a copy of the database no longer sorts its indexes in memory.

On a site with 23 million firewall lines, a copy sorted each index of them in
RAM (temp_store=MEMORY, a fixed 256 MB cache) on a machine whose service may
use 1.8 GB: the daemon went into swap and the copy stood for half an hour on
one index. Now the sort spills to a file beside the copy, the cache is a share
of the memory the service may really use, and the bar and the log say which
index is being built over how many rows.

    ./test/fixes225.py
"""
import json
import os
import sqlite3
import sys
import tempfile
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


src = (ROOT / 'isemon.py').read_text(encoding='utf-8')
print('\nHow much memory a copy is given')
GB = 1024 ** 3
ok('1.8 GB allowed (3.6 GB machine, MemoryMax=50%) -> 76.8 MB', isemon.copy_cache_kib(1.8 * GB), 78643)
ok('a small machine gets no less than 16 MB', isemon.copy_cache_kib(200 * 1024 ** 2), 16 * 1024)
ok('a big one no more than the 256 MB it always had', isemon.copy_cache_kib(64 * GB), 256 * 1024)
ok('memory that cannot be read -> 64 MB', isemon.copy_cache_kib(0), 65536)
may = isemon.memory_we_may_use()
ok('what this machine allows is read (%s)' % isemon.human_size(may), may > 0)
ok('the copy no longer keeps its sorts in memory',
   "'PRAGMA temp_store=MEMORY'" in src.split('def copy_into')[1].split('def read_apart')[0], False)
ok('...it spills them to a file', "'PRAGMA temp_store=FILE'" in src)
ok('...and the cache is worked out, not a fixed 256 MB',
   "'PRAGMA cache_size=-%d' % copy_cache_kib()" in src and "'PRAGMA cache_size=-262144'" not in src)

print('\nWhich index')
ok('a plain one', isemon.index_named('CREATE INDEX IF NOT EXISTS fw_src_ts ON fw_events (srcip, ts)'),
   ('fw_src_ts', 'fw_events'))
ok('a partial one on an expression',
   isemon.index_named('CREATE INDEX IF NOT EXISTS fw_usr_ts ON fw_events (LOWER(usr), ts) WHERE usr <> \'\''),
   ('fw_usr_ts', 'fw_events'))
ok('a unique one, quoted', isemon.index_named('CREATE UNIQUE INDEX "a_b" ON "t" (x)'), ('a_b', 't'))
ok('not an index', isemon.index_named('CREATE TABLE x (a)'), ('', ''))

print('\nA copy, for real')
work = Path(tempfile.mkdtemp(prefix='isemon-225-'))
isemon.STATE_DIR = work
isemon.DB_FILE = work / 'd.db'
isemon.BACKUP_DIR = work / 'backups'
isemon._LOG_PATH = work / 'd.log'
isemon.CONFIG_FILE = work / 'config.json'
(work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
raw = sqlite3.connect(str(isemon.DB_FILE))
cols = [r[1] for r in raw.execute('PRAGMA table_info(fw_events)')]
need = [r for r in raw.execute('PRAGMA table_info(fw_events)') if r[3] and r[4] is None and not r[5]]
rows = []
for i in range(60000):
    one = {c[1]: (0 if c[2].upper().startswith(('INT', 'REAL')) else '') for c in need}
    one.update({'ts': 1761000000 + i, 'srcip': '10.0.%d.%d' % (i // 250 % 250, i % 250),
                'dstip': '192.168.1.%d' % (i % 200), 'ident': 'x%d' % i})
    rows.append(one)
keys = sorted(rows[0])
raw.executemany('INSERT INTO fw_events (%s) VALUES (%s)' % (','.join(keys), ','.join('?' * len(keys))),
                [[r[k] for k in keys] for r in rows])
raw.commit()
raw.close()

seen = []
real_step = isemon.Going.step


def step(self, many=1, total=None):
    seen.append(self.what)
    return real_step(self, many, total)


isemon.Going.step = step
# Table by table, as off PostgreSQL: SQLite's own online backup carries the
# indexes over with the pages and never builds one.
isemon.SqliteDialect.copy_out = isemon.Dialect.copy_out
target = work / 'backups' / 'isemon-test.db'
store.copy_into(target)
isemon.Going.step = real_step
ok('the copy is there, whole', target.exists() and not Path(str(target) + '.part').exists())
c = sqlite3.connect(str(target))
ok('...with every firewall line', c.execute('SELECT COUNT(*) FROM fw_events').fetchone()[0], 60000)
have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
ok('...and the firewall indexes built', {'fw_ts', 'fw_src_ts', 'fw_dst_ts', 'fw_area_ts'} <= have)
ok('...it is sound', c.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
c.close()
ok('the bar says which index, on which table, over how many rows',
   any('building its indexes — fw_src_ts on fw_events, 60,000 row(s)' in w for w in seen), True)
ok('...and still says "building its indexes", which the page goes by',
   all('building its indexes' in w for w in seen if ' on fw_events, ' in w))
ok('the sorts went into the folder of the copy', isemon._COPY_SORTS['set'], str(target.parent))
ok('a line in the log for an index that took long', "built in %s'" in src)

print('\nThe upgrade page')
page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
up = page.split('function upgradeAgain(ms)')[1].split('function loadUpgrade(')[0]
ok('a window in the background re-arms the asking instead of dropping it',
   'if (document.hidden) { upgradeAgain(ms); return; }' in up)
ok('...and it asks at once when the window is looked at again',
   "paneLive('upgrade') && UP.last && UP.last.running) loadUpgrade(true);" in up)
ok('the old one-shot check is gone',
   "if (paneLive('upgrade') && !document.hidden) loadUpgrade(true);" in page, False)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
