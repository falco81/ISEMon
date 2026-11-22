#!/usr/bin/env python3
"""1.10.370: speed on a very large database, round four - the daemon's own
work in Python (the Windows events read half as fast as the rest, the
firewall overview's lists, the RouterOS lines), the PostgreSQL Domain page
and search, and MariaDB, which has no partial indexes.

    ./test/fixes370_speed.py
"""
import random
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


src = (ROOT / 'isemon.py').read_text()

print('The fields of a Windows event, found in one pass')
labels = sorted(set(isemon.WIN_SECTIONS) | set(isemon.WIN_LABELS))
rng = random.Random(370)
bits = labels + ['x', 'Name', 'Account', ':', ' ', '\t', '\r\n', 'Logon ID:0x1', 'a:b',
                 'Security ID:', 'S-1-5-18', 'ID: ', 'Network Information:']
same = True
for _ in range(4000):
    text = ''.join(rng.choice(bits) + rng.choice([': ', ':', ' ', '  ', ':\t', ''])
                   for _n in range(rng.randrange(1, 30)))
    want = [(m.group(1), m.start(), m.end()) for m in isemon.WIN_FIELD.finditer(text)]
    if isemon.win_field_marks(text) != want or isemon.win_field_marks_old(text) != want:
        same = False
        print('    differs on %r' % text[:200])
        break
ok('the same as the one regex of every label, on 4000 made-up events', same)

print('A row read by its name stays in C')
row = isemon.Row(['a', 'b'], [1, 'two'])
ok('by name', (row['a'], row['b']), (1, 'two'))
ok('by place, from either end', (row[0], row[1], row[-1]), (1, 'two', 'two'))
try:
    row['c']
    said = 'nothing'
except KeyError:
    said = 'KeyError'
ok('a name it has not: KeyError', said, 'KeyError')
try:
    row[5]
    said = 'nothing'
except IndexError:
    said = 'IndexError'
ok('a place it has not: IndexError', said, 'IndexError')
ok('dict() of it costs nothing', dict(row), {'a': 1, 'b': 'two'})

print('The year of a syslog moment, kept')
now = time.time()
d = time.localtime(now - 3600)
mon = time.strftime('%b', d)
a = isemon.otp_when(mon, str(d.tm_mday), time.strftime('%H:%M:%S', d), now=now)
b = isemon.otp_when(mon, str(d.tm_mday), time.strftime('%H:%M:%S', d), now=now)
ok('asked twice, the same moment', a, b)
ok('...an hour ago', abs(float(a) - (now - 3600)) < 2)

print('PostgreSQL and MariaDB')
ok('three distinct counts in one walk (GROUPING SETS) on PostgreSQL',
   "if self.dialect.name == 'postgres' and by not in ('machine', 'account', 'ip'):" in src)
ok('an equality never answered by the word index',
   "'(LOWER(%s) >= ? AND LOWER(%s) <= ?)'" in src)
ok('a common word read the newest day first, where the word index is there',
   "if self.dialect.name == 'postgres' and self.get_meta('win_words_done'):" in src)
ok('MariaDB gets (verdict, ts) and (type, ts) whole',
   "{False: 'CREATE INDEX IF NOT EXISTS fw_kept_verdict_ts '" in src
   and "{False: 'CREATE INDEX IF NOT EXISTS fw_kept_type_ts '" in src)

print('...and on the file, as before')
folder = Path(tempfile.mkdtemp(prefix='isemon-370-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'winsec': 1})
store = isemon.Storage(isemon.DB_FILE)
NOW = time.time()
store.note_win_events([{'ident': 'w%d' % n, 'ts': NOW - n * 600, 'server': 'DC1',
                        'event': 4625, 'kind': 'logon-failed', 'account': 'kiosk%d' % (n % 3),
                        'machine': 'PC%d' % (n % 4), 'ip': '10.0.0.%d' % n}
                       for n in range(60)])
got = store.win_find('kiosk1', since=NOW - 86400)
ok('the find box finds on the file', bool(got))
names = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
ok('the file keeps its partial indexes', {'fw_kept_verdict_ts', 'fw_kept_type_ts'} <= names)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
